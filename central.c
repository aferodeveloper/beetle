/********************************************************************************
 *
 * Copyright 2016-2017 Afero, Inc.
 *
 * Licensed under the MIT license (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a copy of the License
 * at
 *
 * https://opensource.org/licenses/MIT
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *******************************************************************************/

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>

#include "babygatt_central.h"
#include "beetle.h"
#include "command.h"
#include "connlist.h"
#include "devicelist.h"
#include "evloop.h"
#include "hci_beetle.h"
#include "log.h"
#include "utils.h"


/* time = n * 0.625 msec; 200 = 1/8 sec */
#define SCAN_INTERVAL 200
#define SCAN_WINDOW SCAN_INTERVAL

/* any connect attempt that takes this long is broken */
#define CONNECT_TIMEOUT 11

/* C is a single-pass parser */
static evloop_handler_result_t handle_l2cap_write(evloop_t *ev, int fd, void *arg);
static evloop_handler_result_t handle_l2cap_read(evloop_t *ev, int fd, void *arg);

/* track advertisements we see per minute, for debugging */
static time_t s_last_adv_update = 0;
static int s_last_adv_count = 0;

/* hide advertisements? */
static bool s_quiet = false;

/*
 * track how many minutes we've gone without seeing any advertisements. if
 * it goes too long, we'll re-emphasize to bluez that we want scan enabled.
 */
static int s_minutes_without_ads = 0;
#define MAX_MINUTES_WITHOUT_ADS 10

/* activate scan on the next event loop (postponed) */
static bool s_activate_scan = false;
static time_t s_last_activate_scan_check = 0;
#define ACTIVATE_SCAN_DELAY_SECONDS 5

/*
 * track failed connections. if we've had too many in a row, the bluez
 * driver has probably gotten wedged, and we need to kill the session and
 * force hubby to reconnect and start over.
 */
static int s_failed_connection_count = 0;
#define MAX_FAILED_CONNECTIONS 10

/*
 * track the receipt of connections that we've already cancelled. bluez
 * sometimes gets into a tight loop, reporting the same cancelled connection
 * over and over until it crashes. we can help out by pulling the plug.
 */
static int s_dead_connection_count = 0;
#define MAX_DEAD_CONNECTION_COUNT 5

/* commands */

struct command_context {
    bhci_t *bhci;
    evloop_t *ev;
    time_t now;
};

int cmd_quiet(void *param1, void *param2, void *param3, void *context) {
    s_quiet = !s_quiet;
    send_cmd("shh %i", s_quiet);
    return 0;
}

/* handle connect command */
int cmd_connect(void *param1, void *param2, void *param3, void *context) {
    char *addr = param1;
    struct command_context *cc = context;

    // find the device address
    device_info_t *di = dl_find_by_addr(addr);
    if (di == NULL) {
        ERROR("unknown device %s", addr);
        send_cmd("con %s %04x %04x", addr, STATUS_UNKNOWN_DEVICE, 0);
        return 0;
    }

    // check if the device is already connected
    conn_info_t *ci = cl_find_by_addr(di->addr);
    if (ci != NULL) {
        ERROR("device %s is already connected", addr);
        send_cmd("con %s %04x %04x", addr, STATUS_ALREADY_CONNECTED, 0);
        return 0;
    }

    // get a free connection handle
    ci = cl_get_unused();
    if (ci == NULL) {
        ERROR("connection list is full");
        send_cmd("con %s %04x %04x", addr, STATUS_CONN_LIST_FULL, 0);
        return 0;
    }

    ci->d_info = di;
    ci->l2cap_fd = -1;
    ci->connect_started = get_mono_time();

    // Get connection ID
    ci->conn_id = 4;
    ci->state = CONN_STATE_CONNECTING;

    // Connect the device
    INFO("device_connect %s %04x %04x", ci->d_info->addr, ci->d_info->addr_type, ci->conn_id);

    if (bhci_device_connect(cc->bhci, di->addr, di->addr_type) < 0) {
        send_cmd("con %s %04x %04x", addr, STATUS_IO_ERROR, 0);
        log_failure("connection create");
        cl_free(ci);
        return 0;
    }

    // continues when we get a "connect" event over HCI...
    return 0;
}

static void cancel_connect(bhci_t *bhci, evloop_t *ev, conn_info_t *ci) {
    s_failed_connection_count++;
    switch (ci->state) {
        case CONN_STATE_CONNECTING:
            DEBUG("cancel %s: sending cancel request", ci->d_info->addr);
            bhci_cancel_device_connect(bhci);
            break;
        case CONN_STATE_CONNECTING_L2CAP:
            DEBUG("cancel %s: abandoning incomplete l2cap socket", ci->d_info->addr);
            break;
        case CONN_STATE_CONNECTED:
            DEBUG("cancel %s: closing l2cap socket", ci->d_info->addr);
            close(ci->l2cap_fd);
            evloop_cancel_read(ev, ci->l2cap_fd);
            break;
    }
    cl_free(ci);
}

int cmd_cancel_connect(void *param1, void *param2, void *param3, void *context) {
    char *addr = param1;
    struct command_context *cc = context;

    // check if the device is already connected
    conn_info_t *ci = cl_find_by_addr(addr);
    if (ci == NULL) {
        ERROR("cancel %s: no such connection", addr);
        send_cmd("can %s %04x", addr, STATUS_UNKNOWN_CONN);
        return 0;
    }

    switch (ci->state) {
        case CONN_STATE_DISCONNECTED:
        case CONN_STATE_DISCONNECTING:
            DEBUG("cancel %s: not connected", addr);
            send_cmd("can %s %04x", addr, STATUS_NOT_CONNECTED);
            break;
        default:
            cancel_connect(cc->bhci, cc->ev, ci);
            s_activate_scan = true;
            send_cmd("can %s %04x", addr, STATUS_OK);
            break;
    }

    return 0;
}

int cmd_disconnect(void *param1, void *param2, void *param3, void *context) {
    int l2cap_fd = *(int *)param1;
    struct command_context *cc = context;
    conn_info_t *ci = cl_find_by_l2cap_fd(&l2cap_fd);

    if (ci == NULL) {
        ERROR("l2cap_fd %d not found", l2cap_fd);
        send_cmd("dis %04x %04x", l2cap_fd, STATUS_UNKNOWN_CONN);
        return 0;
    }

    DEBUG("disconnecting %s", ci->d_info->addr);
    ci->state = CONN_STATE_DISCONNECTING;
    shutdown(ci->l2cap_fd, SHUT_WR);
    evloop_cancel_read(cc->ev, ci->l2cap_fd);
    return 0;
}


/* HCI callbacks */

static void handle_disconnect(bhci_t *bhci, evt_disconn_complete *disconn, void *arg) {
    evloop_t *ev = arg;
    uint16_t handle = btohs(disconn->handle);
    conn_info_t *ci = cl_find_by_hci_handle(&handle);
    if (ci == NULL) return;

    close(ci->l2cap_fd);
    evloop_cancel_read(ev, ci->l2cap_fd);
    gatt_fail_any_pending(ci, STATUS_TIMED_OUT);
    send_cmd("dis %04x %04x %04x", ci->l2cap_fd, STATUS_OK, disconn->reason);
    cl_free(ci);
    s_activate_scan = true;
}

static void handle_connect(bhci_t *bhci, evt_le_connection_complete *conn, char *addr, void *arg) {
    evloop_t *ev = arg;
    conn_info_t *ci = cl_find_by_addr(addr);
    device_info_t *di = dl_find_by_addr(addr);

    if (di == NULL) {
        ERROR("no such device %s", addr);
        return;
    }

    // Create L2CAP connection
    uint16_t handle = btohs(conn->handle);
    int fd = bhci_l2cap_connect(addr, 4, di->addr_type);

    if (ci == NULL) {
        DEBUG("received dead connection; ignoring");
        close(fd);
        s_activate_scan = true;
        // sometimes, bluez gets in a loop, dumping these over and over.
        s_dead_connection_count++;
        if (s_dead_connection_count > MAX_DEAD_CONNECTION_COUNT) {
            evloop_stop(ev, SESSION_REBUILD_BLUETOOTH);
        }
        return;
    }

    s_dead_connection_count = 0;
    if (ci->state != CONN_STATE_CONNECTING) {
        ERROR("connection to %s finished, but we didn't want it", addr);
        close(fd);
        s_activate_scan = true;
        return;
    }

    ci->hci_handle = handle;
    ci->l2cap_fd = fd;
    DEBUG("l2cap_connect %s fd=%d", addr, ci->l2cap_fd);

    /* making an l2cap connection tends to kill our scan */
    s_activate_scan = true;

    if (fd < 0) {
        send_cmd("con %s %04x %04x", addr, STATUS_L2CAP_CONN_FAILED, 0);
        cl_free(ci);
        return;
    } else {
        ci->state = CONN_STATE_CONNECTING_L2CAP;
        evloop_on_write(ev, fd, handle_l2cap_write, NULL);
    }
}

static void handle_advertisement(bhci_t *bhci, uint8_t *data, int len, void *arg) {
    uint8_t report_count = data[0];
    data++, len--;

    int i;
    for (i = 0; i < report_count && len > 0; i++) {
        if (len < sizeof(le_advertising_info)) {
          DEBUG("Truncated advertisement header");
          return;
        }

        le_advertising_info *advertisement = (le_advertising_info *)data;
        data += sizeof(le_advertising_info), len -= sizeof(le_advertising_info);
        if (len < advertisement->length) {
          DEBUG("Truncated advertisement header");
          return;
        }

        char addr[BT_ADDR_SIZE];
        uint8_t afero_device = 0;
        char manufacturer_data[32];

        addr2str(&advertisement->bdaddr, addr);

        int j = 0;
        while (j < advertisement->length) {
            uint8_t field_len = data[j];
            if (
                j + field_len < advertisement->length &&
                data[j + 1] == 0xff &&
                data[j + 2] == 0xd2 &&
                data[j + 3] == 0x02
            ) {
                afero_device = 1;
                data2hex(manufacturer_data, sizeof(manufacturer_data), data + j + 2, field_len - 1);
            }
            j += field_len + 1;
        }

        data += advertisement->length, len -= advertisement->length;
        int8_t rxpower = *(int8_t *)data;
        data++, len--;

        if (afero_device) {
            device_info_t *device = dl_add_device(addr, advertisement->bdaddr_type);
            if (device != NULL) {
                device->rssi = rxpower;
            }
            if (!s_quiet) send_cmd("adv %s %s %d", addr, manufacturer_data, rxpower);
            s_last_adv_count++;
        }
    }
}

static void handle_desync(bhci_t *bhci, void *arg) {
    evloop_t *ev = arg;
    evloop_stop(ev, SESSION_REBUILD_BLUETOOTH);
}


/* cleanup */

static void handle_l2cap_close(conn_info_t *ci, void *arg) {
    close(ci->l2cap_fd);
    cl_free(ci);
}

static void handle_l2cap_close_loudly(conn_info_t *ci, void *arg) {
    gatt_fail_any_pending(ci, STATUS_TIMED_OUT);
    send_cmd("dis %04x %04x %04x", ci->l2cap_fd, STATUS_OK, 0);
    handle_l2cap_close(ci, arg);
}

static void handle_l2cap_cancel(conn_info_t *ci, void *arg) {
    gatt_fail_any_pending(ci, STATUS_TIMED_OUT);
    send_cmd("con %s %04x %04x", ci->d_info->addr, STATUS_L2CAP_CONN_FAILED, 0);
    handle_l2cap_close(ci, arg);
}

static void handle_connect_cancel(conn_info_t *ci, void *arg) {
    bhci_t *bhci = arg;
    send_cmd("con %s %04x %04x", ci->d_info->addr, STATUS_L2CAP_CONN_FAILED, 0);
    bhci_cancel_device_connect(bhci);
    cl_free(ci);
}

static void check_connect_timeout(conn_info_t *ci, void *arg) {
    struct command_context *cc = arg;
    if (ci->connect_started == 0) return;
    if (cc->now - ci->connect_started <= CONNECT_TIMEOUT) return;

    s_failed_connection_count++;
    DEBUG("connect timeout on %s", ci->d_info->addr);
    cancel_connect(cc->bhci, cc->ev, ci);
    send_cmd("con %s %04x %04x", ci->d_info->addr, STATUS_TIMED_OUT, 0);
}


/* event loop handlers */

static evloop_handler_result_t handle_hci_read(evloop_t *ev, int fd, void *arg) {
    bhci_read((bhci_t *) arg);
    return EL_CONTINUE;
}

static evloop_handler_result_t handle_client_read(evloop_t *ev, int fd, void *arg) {
    bhci_t *bhci = arg;
    struct command_context cc = {
        .bhci = bhci,
        .ev = ev,
        .now = get_mono_time()
    };
    int rv = read_and_execute_client_command(fd, &cc);
    if (rv < 0) evloop_stop(ev, rv);
    return EL_CONTINUE;
}

static evloop_handler_result_t handle_l2cap_write(evloop_t *ev, int fd, void *arg) {
    conn_info_t *ci = cl_find_by_l2cap_fd(&fd);
    if (ci == NULL) {
        ERROR("event for unknown l2cap fd=%i", fd);
        close(fd);
        return EL_STOP;
    }

    int err = 0;
    socklen_t err_len = sizeof(int);
    if (getsockopt(ci->l2cap_fd, SOL_SOCKET, SO_ERROR, &err, &err_len) < 0 || err != 0) {
        ERROR("l2cap connect fd=%d error %d: %s", ci->l2cap_fd, err, strerror(err));
        close(ci->l2cap_fd);
        send_cmd("con %s %04x %04x", ci->d_info->addr, STATUS_L2CAP_CONN_FAILED, 0);
        cl_free(ci);
        return EL_STOP;
    }

    DEBUG("l2cap connect successful");
    s_failed_connection_count = 0;
    ci->state = CONN_STATE_CONNECTED;
    send_cmd("con %s %04x %04x", ci->d_info->addr, STATUS_OK, ci->l2cap_fd);
    evloop_on_read(ev, fd, handle_l2cap_read, NULL);
    return EL_STOP;
}

static evloop_handler_result_t handle_l2cap_read(evloop_t *ev, int fd, void *arg) {
    conn_info_t *ci = cl_find_by_l2cap_fd(&fd);
    if (ci == NULL) {
        ERROR("event for unknown l2cap fd=%i", fd);
        return EL_STOP;
    }

    uint8_t response[1024];
    char hex_data[2048];
    int len = read(ci->l2cap_fd, response, sizeof(response));
    if (len > 0) {
        TRACE("l2r %04x %s", ci->l2cap_fd, data2hex(hex_data, sizeof(hex_data), response, len));
        on_central_data(ci, response, len);
        return EL_CONTINUE;
    } else {
        ERROR("l2 read error %s disconnecting %d", strerror(errno), ci->l2cap_fd);
        ci->state = CONN_STATE_DISCONNECTING;
        close(ci->l2cap_fd);
        return EL_STOP;
    }
}

static evloop_handler_result_t handle_sigusr1(evloop_t *ev, int signal, void *arg) {
    bhci_t *bhci = arg;
    dl_debug();
    bhci_debug_connections(bhci);
    return EL_CONTINUE;
}

static evloop_handler_result_t handle_sigusr2(evloop_t *ev, int signal, void *arg) {
    INFO("SIGUSR2: force bluetooth reset");
    evloop_stop(ev, SESSION_REBUILD_BLUETOOTH);
    return EL_STOP;
}

static evloop_handler_result_t handle_periodic(evloop_t *ev, int signal, void *arg) {
    bhci_t *bhci = arg;
    struct command_context cc = {
        .bhci = bhci,
        .ev = ev,
        .now = get_mono_time()
    };

    /* expire devices that haven't been seen for a while */
    dl_expire_devices();

    /* cancel any connections that have timed out */
    cl_foreach_state(CONN_STATE_CONNECTING, check_connect_timeout, &cc);
    cl_foreach_state(CONN_STATE_CONNECTING_L2CAP, check_connect_timeout, &cc);

    if (cc.now - s_last_adv_update >= 60) {
        DEBUG("relayed %i advertisements", s_last_adv_count);
        if (s_last_adv_count == 0) {
            s_minutes_without_ads++;
            if (s_minutes_without_ads > MAX_MINUTES_WITHOUT_ADS) {
                s_activate_scan = true;
                s_minutes_without_ads = 0;
            }
        } else {
            s_minutes_without_ads = 0;
        }

        s_last_adv_count = 0;
        s_last_adv_update = cc.now;
    }

    if (cc.now - s_last_activate_scan_check >= ACTIVATE_SCAN_DELAY_SECONDS) {
        if (s_activate_scan) {
            DEBUG("delayed scan activate!");
            bhci_set_scan_parameters(bhci, SCAN_INTERVAL, SCAN_WINDOW);
            bhci_enable_scan(bhci);
        }
        s_activate_scan = false;
        s_last_activate_scan_check = cc.now;
    }

    if (s_failed_connection_count >= MAX_FAILED_CONNECTIONS) {
        ERROR("failed to connect %i times in a row: reset bluetooth", s_failed_connection_count);
        s_failed_connection_count = 0;
        evloop_stop(ev, SESSION_REBUILD_BLUETOOTH);
        return EL_STOP;
    }

    return EL_CONTINUE;
}


/* main loop */

int central_session(int client_fd, bhci_t *bhci) {
    s_minutes_without_ads = 0;
    s_failed_connection_count = 0;
    s_dead_connection_count = 0;

    if (bhci_set_scan_parameters(bhci, SCAN_INTERVAL, SCAN_WINDOW) < 0) return SESSION_FAILED_NONFATAL;
    if (bhci_enable_scan(bhci) < 0) return SESSION_FAILED_NONFATAL;

    INFO("starting central session: hci_fd=%d", bhci->fd);

    /* close any existing HCI connections */
    bhci_kill_all_connections(bhci);

    /* clear the connection list */
    cl_init();

    evloop_t ev;
    evloop_init(&ev);

    bhci_clear_callbacks(bhci);
    bhci_on_disconnect(bhci, handle_disconnect, &ev);
    bhci_on_connect(bhci, handle_connect, &ev);
    bhci_on_advertisement(bhci, handle_advertisement, NULL);
    bhci_on_desync(bhci, handle_desync, &ev);

    evloop_on_read(&ev, bhci->fd, handle_hci_read, bhci);
    evloop_on_read(&ev, client_fd, handle_client_read, bhci);
    evloop_on_signal(&ev, SIGUSR1, handle_sigusr1, bhci);
    evloop_on_signal(&ev, SIGUSR2, handle_sigusr2, bhci);
    evloop_periodic(&ev, handle_periodic, bhci);

    if (evloop_run(&ev) != EL_STOPPED) return SESSION_FAILED_FATAL;

    INFO("closing central session");

    // stop scanning
    bhci_disable_scan(bhci);

    // close all connections
    cl_foreach_state(CONN_STATE_CONNECTING, handle_connect_cancel, bhci);
    cl_foreach_state(CONN_STATE_CONNECTING_L2CAP, handle_l2cap_cancel, NULL);
    cl_foreach_state(CONN_STATE_CONNECTED, handle_l2cap_close_loudly, NULL);
    cl_foreach_state(CONN_STATE_DISCONNECTING, handle_l2cap_close_loudly, NULL);

    int result_code = ev.result_code;
    evloop_free(&ev);
    return result_code;
}
