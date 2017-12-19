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

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <fcntl.h>
#include <stdarg.h>

#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>

#include "babygatt_peripheral.h"
#include "beetle.h"
#include "command.h"
#include "devicelist.h"
#include "evloop.h"
#include "log.h"
#include "peripheral.h"
#include "utils.h"


#define PERIPHERAL_BUFFER_SIZE 256

#define ADVERTISEMENT_SIZE 31

static int s_advertising = 0;

/* disconnect any client */
int cmd_per_disconnect(void *param1, void *param2, void *param3, void *arg) {
    struct peripheral_context *context = arg;
    if (context->connection_fd >= 0) {
        INFO("disconnecting %s", context->addr);
        close(context->connection_fd);
        evloop_cancel_read(context->ev, context->connection_fd);
        context->connection_fd = -1;
        send_cmd("pdi %s", context->addr);
        context->addr[0] = 0;
    } else {
        send_cmd("pdi");
    }

    if (s_advertising) bhci_enable_advertising(context->bhci);
    return 0;
}

/* construct advertising data */
int cmd_per_advertisement(void *param1, void *param2, void *param3, void *arg) {
    uint8_t flags = (uint8_t)*(int *)param1;
    uint16_t appearance = (uint16_t)*(int *)param2;
    char *data = (char *)param3;
    struct peripheral_context *context = arg;

    uint8_t mfgData[32];
    if (strlen(data) == 0) {
        send_cmd("pad %04x", STATUS_BAD_PARAM);
        return 0;
    }
    int len = hex2data(data, mfgData, sizeof(mfgData));

    uint8_t i = 0;

    uint8_t adv_data[ADVERTISEMENT_SIZE];
    /* set up flags */
    adv_data[i++] = 0x02; /* flags length */
    adv_data[i++] = 0x01; /* flags type */
    adv_data[i++] = flags;
    adv_data[i++] = 0x03; /* appearance length */
    adv_data[i++] = 0x19; /* appearance type */
    adv_data[i++] = appearance % 256; /* little endian */
    adv_data[i++] = appearance / 256;
    adv_data[i++] = (uint8_t)len + 1;
    adv_data[i++] = 0xff; /* mfgData type */
    memcpy(&adv_data[i], mfgData, len);

    if (bhci_set_advertising_data(context->bhci, adv_data, i + len) < 0) {
        send_cmd("pad %04x", STATUS_IO_ERROR);
        return 0;
    }

    if (bhci_enable_advertising(context->bhci) < 0) {
        send_cmd("pad %04x", STATUS_IO_ERROR);
        return 0;
    }

    s_advertising = 1;
    send_cmd("pad %04x", STATUS_OK);
    return 0;
}

static evloop_handler_result_t handle_hci_read(evloop_t *ev, int fd, void *arg) {
    bhci_read((bhci_t *) arg);
    return EL_CONTINUE;
}

static evloop_handler_result_t handle_client_read(evloop_t *ev, int fd, void *arg) {
    struct peripheral_context *context = arg;

    int rv = read_and_execute_client_command(fd, context);
    if (rv < 0) evloop_stop(ev, rv);
    return EL_CONTINUE;
}

static evloop_handler_result_t handle_connection_read(evloop_t *ev, int fd, void *arg) {
    struct peripheral_context *context = arg;

    uint8_t buffer[PERIPHERAL_BUFFER_SIZE];
    ssize_t len = recv(fd, buffer, sizeof(buffer), 0);
    if (len == 0 || (len < 0 && errno == ECONNRESET)) {
        INFO("peripheral closed socket");
        close(fd);
        context->connection_fd = -1;
        send_cmd("pdi %s", context->addr);
        context->addr[0] = 0;
        if (s_advertising) bhci_enable_advertising(context->bhci);
        return EL_STOP;
    }

    if (len < 0) {
        log_failure("read peripheral");
        return ((errno == EAGAIN || errno == EBUSY) ? EL_CONTINUE : EL_STOP);
    }

    on_peripheral_data(buffer, len, context->connection_fd);
    return EL_CONTINUE;
}

static evloop_handler_result_t handle_listener_read(evloop_t *ev, int listen_fd, void *arg) {
    struct peripheral_context *context = arg;

    struct sockaddr_l2 addr;
    socklen_t len = sizeof(addr);
    int fd = accept(listen_fd, (struct sockaddr *)&addr, &len);
    if (fd < 0) {
        log_failure("accept");
        return EL_CONTINUE;
    }

    if (s_advertising) bhci_enable_advertising(context->bhci);

    if (context->connection_fd >= 0) {
        DEBUG("extra hub connection when we already have one: killing it");
        close(fd);
        return EL_CONTINUE;
    }
    context->connection_fd = fd;

    ba2str(&addr.l2_bdaddr, context->addr);
    send_cmd("pco %s", context->addr);
    evloop_on_read(ev, fd, handle_connection_read, context);
    return EL_CONTINUE;
}

static void handle_disconnect(struct bhci *bhci, evt_disconn_complete *disconn, void *arg) {
    /*
     * sometimes, we seem to get a rapid connect/disconnect that doesn't
     * trigger accept(). make sure we're still advertising.
     */
    if (s_advertising) bhci_enable_advertising(bhci);
}

static evloop_handler_result_t handle_sigusr1(evloop_t *ev, int signal, void *arg) {
    dl_debug();
    return EL_CONTINUE;
}

static evloop_handler_result_t handle_sigusr2(evloop_t *ev, int signal, void *arg) {
    evloop_stop(ev, SESSION_REBUILD_BLUETOOTH);
    return EL_STOP;
}

int peripheral_session(int client_fd, bhci_t *bhci) {
    struct peripheral_context context = {
        .listen_fd = bhci_listen(bhci),
        .connection_fd = -1,
        .bhci = bhci,
        .ev = NULL
    };

    if (context.listen_fd < 0) return SESSION_FAILED_NONFATAL;

    uint16_t adv_min = 400;   /* 250 ms / 0.625 ms */
    uint16_t adv_max = 800;   /* 500 ms / 0.625 ms */
    if (bhci_set_advertising_parameters(bhci, adv_min, adv_max) < 0) {
        close(context.listen_fd);
        return SESSION_FAILED_NONFATAL;
    }

    INFO("starting peripheral session: hci_fd=%d, listen_fd=%d", bhci->fd, context.listen_fd);
    s_advertising = 0;

    evloop_t ev;
    evloop_init(&ev);
    context.ev = &ev;

    bhci_clear_callbacks(bhci);
    bhci_on_disconnect(bhci, handle_disconnect, &context);

    evloop_on_read(&ev, bhci->fd, handle_hci_read, bhci);
    evloop_on_read(&ev, context.listen_fd, handle_listener_read, &context);
    evloop_on_read(&ev, client_fd, handle_client_read, &context);
    evloop_on_signal(&ev, SIGUSR1, handle_sigusr1, NULL);
    evloop_on_signal(&ev, SIGUSR2, handle_sigusr2, NULL);

    if (evloop_run(&ev) != EL_STOPPED) return SESSION_FAILED_FATAL;

    INFO("closing peripheral session");

    bhci_disable_advertising(bhci);

    if (context.connection_fd >= 0) {
        close(context.connection_fd);
        send_cmd("pdi %s", context.addr);
    }
    close(context.listen_fd);

    int result_code = ev.result_code;
    evloop_free(&ev);
    return result_code;
}
