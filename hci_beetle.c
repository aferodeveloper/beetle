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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>

#include "beetle.h"
#include "hci_beetle.h"
#include "log.h"
#include "utils.h"

#define MAX_CONNECTIONS 16

/*
 * Wrappers for bluetooth HCI
 */

int bhci_open(bhci_t *bhci, const char *interface_name) {
    bhci_clear_callbacks(bhci);

    int dev_id = interface_name ? hci_devid(interface_name) : hci_get_route(NULL);
    if (dev_id < 0) {
        log_failure("hci_devid/hci_get_route");
        return -1;
    }

    /* try to get own address */
    if (hci_devba(dev_id, &bhci->own_address) < 0) {
        log_failure("hci_devba");
        return -1;
    }
    bhci->fd = hci_open_dev(dev_id);
    if (bhci->fd < 0) {
        log_failure("hci_open_dev");
        return -1;
    }
    return 0;
}

void bhci_clear_callbacks(bhci_t *bhci) {
    bhci->on_disconnect = NULL;
    bhci->on_disconnect_arg = NULL;
    bhci->on_connect = NULL;
    bhci->on_connect_arg = NULL;
    bhci->on_advertisement = NULL;
    bhci->on_advertisement_arg = NULL;
}

void bhci_close(bhci_t *bhci) {
    close(bhci->fd);
    bhci_clear_callbacks(bhci);
    bhci->fd = -1;
    memset(&bhci->own_address, 0, sizeof(bhci->own_address));
}

int bhci_set_scan_enable(bhci_t *bhci, uint8_t enable) {
    le_set_scan_enable_cp scan_cp;

    memset(&scan_cp, 0, sizeof(scan_cp));
    scan_cp.enable = enable;
    scan_cp.filter_dup = 0;

    if (hci_send_cmd(bhci->fd, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE, sizeof(scan_cp), &scan_cp) < 0) {
        log_failure("bhci_set_scan_enable");
        return -1;
    }
    return 0;
}

int bhci_set_advertising_enable(bhci_t *bhci, uint8_t enable) {
    le_set_advertise_enable_cp adv_cp;

    memset(&adv_cp, 0, sizeof(adv_cp));
    adv_cp.enable = enable;

    if (hci_send_cmd(bhci->fd, OGF_LE_CTL, OCF_LE_SET_ADVERTISE_ENABLE, sizeof(adv_cp), &adv_cp) < 0) {
        log_failure("bhci_set_scan_enable");
        return -1;
    }
    return 0;
}

int bhci_disconnect(bhci_t *bhci, uint16_t handle) {
    disconnect_cp dis_cp;

    memset(&dis_cp, 0, sizeof(dis_cp));
    dis_cp.handle = htobs(handle);
    dis_cp.reason = HCI_CONNECTION_TERMINATED;

    if (hci_send_cmd(bhci->fd, OGF_LINK_CTL, OCF_DISCONNECT, sizeof(dis_cp), &dis_cp) < 0) {
        log_failure("bhci_disconnect");
        return -1;
    }
    return 0;
}

/*
 * clear all filters, and set the scan parameters.
 */
int bhci_set_scan_parameters(bhci_t *bhci, int interval, int window) {
    le_set_scan_parameters_cp scan_cp;
    struct hci_filter flt;

    hci_filter_clear(&flt);
    hci_filter_all_ptypes(&flt);
    hci_filter_all_events(&flt);
    if (setsockopt(bhci->fd, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
        log_failure("HCI_FILTER");
        return -1;
    }

    memset(&scan_cp, 0, sizeof(scan_cp));
    scan_cp.type = 0;
    scan_cp.interval = htobs(interval);
    scan_cp.window = htobs(window);
    scan_cp.own_bdaddr_type = 0;
    scan_cp.filter = 0;

    if (hci_send_cmd(bhci->fd, OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMETERS, sizeof(scan_cp), &scan_cp) < 0) {
        log_failure("bhci_set_scan_parameters");
        return -1;
    }
    return 0;
}

static const char *bhci_conn_state(uint16_t state) {
    switch (state) {
        case BT_CONNECTED:
            return "BT_CONNECTED";
        case BT_OPEN:
            return "BT_OPEN";
        case BT_BOUND:
            return "BT_BOUND";
        case BT_LISTEN:
            return "BT_LISTEN";
        case BT_CONNECT:
            return "BT_CONNECT";
        case BT_CONNECT2:
            return "BT_CONNECT2";
        case BT_CONFIG:
            return "BT_CONFIG";
        case BT_DISCONN:
            return "BT_DISCONN";
        case BT_CLOSED:
            return "BT_CLOSED";
        default:
            return "unknown";
    }
}

static struct hci_conn_list_req *bhci_get_connection_list(bhci_t *bhci) {
    struct hci_conn_list_req *cl = malloc(MAX_CONNECTIONS * sizeof(struct hci_conn_info) + sizeof(*cl));
    cl->dev_id = 0;
    cl->conn_num = MAX_CONNECTIONS;
    if (ioctl(bhci->fd, HCIGETCONNLIST, (void *) cl)) {
        free(cl);
        log_failure("HCIGETCONNLIST");
        return NULL;
    }
    return cl;
}

int bhci_debug_connections(bhci_t *bhci) {
    struct hci_conn_list_req *cl = bhci_get_connection_list(bhci);
    if (!cl) return -1;

    DEBUG("--- HCI connection list:");
    int i;
    for (i = 0; i < cl->conn_num; i++) {
        struct hci_conn_info *ci = &cl->conn_info[i];
        char addr[18];
        addr2str(&ci->bdaddr, addr);
        DEBUG("conn %i: %s handle=%i state=%s", i, addr, btohs(ci->handle), bhci_conn_state(ci->state));
    }
    DEBUG("--- End of HCI connection list");
    free(cl);
    return 0;
}

int bhci_kill_all_connections(bhci_t *bhci) {
    struct hci_conn_list_req *cl = bhci_get_connection_list(bhci);
    if (!cl) return -1;

    int i;
    for (i = 0; i < cl->conn_num; i++) {
        struct hci_conn_info *ci = &cl->conn_info[i];
        if (ci->state == BT_CONNECTED) {
            char addr[18];
            addr2str(&ci->bdaddr, addr);
            INFO("Disconnecting %s", addr);
            bhci_disconnect(bhci, btohs(ci->handle));
        }
    }

    free(cl);
    return 0;
}

int bhci_device_connect(bhci_t *bhci, const char *addr, uint8_t addr_type) {
    le_create_connection_cp create_conn_cp;

    /* build the UART packet directly */
    memset(&create_conn_cp, 0, sizeof(create_conn_cp));
    create_conn_cp.interval = htobs(0x00a0);
    create_conn_cp.window = htobs(0x00a0);
    create_conn_cp.initiator_filter = 0;
    create_conn_cp.peer_bdaddr_type = addr_type;
    str2ba(addr, &create_conn_cp.peer_bdaddr);
    create_conn_cp.own_bdaddr_type = LE_PUBLIC_ADDRESS;
    create_conn_cp.min_interval = htobs(0x0013);
    create_conn_cp.max_interval = htobs(0x0013);
    create_conn_cp.latency = htobs(0x0009);
    create_conn_cp.supervision_timeout = htobs(0x0190);
    create_conn_cp.min_ce_length = htobs(0x0000);
    create_conn_cp.max_ce_length = htobs(0x0000);

    if (hci_send_cmd(bhci->fd, OGF_LE_CTL, OCF_LE_CREATE_CONN, sizeof(create_conn_cp), &create_conn_cp) < 0) {
        log_failure("bhci_device_connect");
        return -1;
    }
    return 0;
}

/* cancel whatever the current connection is */
int bhci_cancel_device_connect(bhci_t *bhci) {
    if (hci_send_cmd(bhci->fd, OGF_LE_CTL, OCF_LE_CREATE_CONN_CANCEL, 0, NULL) < 0) {
        log_failure("bhci_cancel_device_connect");
        return -1;
    }
    return 0;
}

int bhci_listen(bhci_t *bhci) {
    int fd = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
    if (fd < 0) {
        log_failure("bhci_listen:socket");
        return -1;
    }

    /* set up the local address */
    struct sockaddr_l2 localAddr;
    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.l2_family = AF_BLUETOOTH;
    localAddr.l2_cid = htobs(0x04);
    localAddr.l2_bdaddr_type = BDADDR_LE_PUBLIC;
    localAddr.l2_bdaddr = bhci->own_address;

    if (bind(fd, (struct sockaddr *) &localAddr, sizeof(localAddr)) < 0) {
        log_failure("bhci_listen:bind");
        close(fd);
        return -1;
    }

    struct bt_security sec;
    memset(&sec, 0, sizeof(sec));
    sec.level = BT_SECURITY_LOW;
    if (setsockopt(fd, SOL_BLUETOOTH, BT_SECURITY, &sec, sizeof(sec)) < 0) {
        log_failure("bhci_listen:setsockopt");
        close(fd);
        return -1;
    }

    if (listen(fd, 1) < 0) {
        log_failure("bhci_listen:listen");
        close(fd);
        return -1;
    }

    return fd;
}

int bhci_set_advertising_parameters(bhci_t *bhci, uint16_t min_interval, uint16_t max_interval) {
    le_set_advertising_parameters_cp adv_cp;

    /* build the UART packet directly */
    memset(&adv_cp, 0, sizeof(adv_cp));
    adv_cp.min_interval = htobs(min_interval);
    adv_cp.max_interval = htobs(max_interval);
    adv_cp.advtype = 0;
    adv_cp.own_bdaddr_type = LE_PUBLIC_ADDRESS;
    adv_cp.chan_map = 7;
    adv_cp.filter = 0;

    if (hci_send_cmd(bhci->fd, OGF_LE_CTL, OCF_LE_SET_ADVERTISING_PARAMETERS, sizeof(adv_cp), &adv_cp) < 0) {
        log_failure("bhci_set_advertising_parameters");
        return -1;
    }
    return 0;
}

int bhci_set_advertising_data(bhci_t *bhci, uint8_t *data, int len) {
    le_set_advertising_data_cp data_cp;

    /* build the UART packet directly */
    memset(&data_cp, 0, sizeof(data_cp));
    data_cp.length = len;
    memcpy(&data_cp.data, data, len);
    if (hci_send_cmd(bhci->fd, OGF_LE_CTL, OCF_LE_SET_ADVERTISING_DATA, sizeof(data_cp), &data_cp) < 0) {
        log_failure("bhci_set_advertising_data");
        return -1;
    }
    return 0;
}

/* open a non-blocking L2CAP socket to a device */
int bhci_l2cap_connect(const char* addr, int cid, int addr_type) {
    DEBUG("bhci_l2cap_connect: %s %d", addr, addr_type);

    int fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET | SOCK_NONBLOCK, BTPROTO_L2CAP);
    if (fd < 0) {
        log_failure("bhci_l2cap_connect:socket");
        return -1;
    }

    /* set the socket type to l2cap */
    struct sockaddr_l2 sockAddr;
    memset(&sockAddr, 0, sizeof(sockAddr));
    sockAddr.l2_family = AF_BLUETOOTH;
    sockAddr.l2_cid = htobs(cid);

    if (bind(fd, (struct sockaddr*) &sockAddr, sizeof(sockAddr)) < 0) {
        log_failure("bind");
        return -1;
    }

    /* connect to the device */
    str2ba(addr, &sockAddr.l2_bdaddr);
    sockAddr.l2_bdaddr_type = (addr_type ? BDADDR_LE_RANDOM : BDADDR_LE_PUBLIC);

    if (connect(fd, (struct sockaddr *) &sockAddr, sizeof(sockAddr)) < 0) {
        if (errno != EINPROGRESS) {
            close(fd);
            log_failure("connect");
            DEBUG("connect failed fd=%i", fd);
            return -1;
        }
    }
    return fd;
}

static char *ogf_ocf_name(char *buffer, size_t len, uint16_t opcode) {
    /* opcode: (OGF << 10) | OCF */
    uint16_t ogf = (opcode >> 10) & 0x3f;
    uint16_t ocf = opcode & 0x3ff;

#define friendly(_name) strncpy(buffer, _name, len); buffer[len - 1] = 0; break

    switch (ogf) {
        case OGF_LINK_CTL:  // 0x01
            switch (ocf) {
                case OCF_DISCONNECT:  // 0x006
                    friendly("DISCONNECT");
            }
            break;

        case OGF_LE_CTL:  // 0x08
            switch (ocf) {
                case OCF_LE_SET_ADVERTISING_PARAMETERS:  // 0x006
                    friendly("SET_ADVERTISING_PARAMETERS");
                case OCF_LE_SET_ADVERTISING_DATA:  // 0x008
                    friendly("SET_ADVERTISING_DATA");
                case OCF_LE_SET_ADVERTISE_ENABLE:  // 0x00a
                    friendly("SET_ADVERTISE_ENABLE");
                case OCF_LE_SET_SCAN_PARAMETERS:  // 0x00b
                    friendly("SET_SCAN_PARAMETERS");
                case OCF_LE_SET_SCAN_ENABLE:  // 0x00c
                    friendly("SET_SCAN_ENABLE");
                case OCF_LE_CREATE_CONN:  // 0x00d
                    friendly("CREATE_CONN");
                case OCF_LE_CREATE_CONN_CANCEL:  // 0x00e
                    friendly("CREATE_CONN_CANCEL");
                case OCF_LE_ADD_DEVICE_TO_WHITE_LIST:  // 0x011
                    friendly("ADD_DEVICE_TO_WHITE_LIST");
                case OCF_LE_REMOVE_DEVICE_FROM_WHITE_LIST:  // 0x012
                    friendly("REMOVE_DEVICE_FROM_WHITE_LIST");
                case OCF_LE_READ_REMOTE_USED_FEATURES:  // 0x016
                    friendly("READ_REMOTE_USED_FEATURES");
                default:
                    snprintf(buffer, len, "ogf=0x%02x ocf=0x%03x", ogf, ocf);
            }
            break;

        default:
            snprintf(buffer, len, "ogf=0x%02x ocf=0x%03x", ogf, ocf);
    }

#undef friendly

    return buffer;
}

/* call me when the HCI socket polls as "readable" */
void bhci_read(bhci_t *bhci) {
    uint8_t buffer[HCI_MAX_FRAME_SIZE];
    char hex_data[HCI_MAX_FRAME_SIZE * 2 + 1];
    ssize_t len = recv(bhci->fd, buffer, sizeof(buffer), 0);

    if (len <= 0) {
        log_failure("HCI read");
        return;
    }
    if (len < 3) {
        ERROR("ignoring truncated bluetooth packet (len=%zi)", len);
        return;
    }

    if (buffer[0] != HCI_EVENT_PKT) return;
    uint8_t event = buffer[1];
    void *data = &buffer[3];
    int data_len = len - 3;

    switch (event) {
        case EVT_CMD_STATUS:
            if (data_len >= sizeof(evt_cmd_status)) {
                evt_cmd_status *status = data;
                DEBUG("evt_cmd_status %s status=0x%02x",
                  ogf_ocf_name(hex_data, sizeof(hex_data), htobs(status->opcode)), status->status);
            }
            break;

        case EVT_CMD_COMPLETE:
            if (data_len >= sizeof(evt_cmd_complete)) {
                evt_cmd_complete *cc = data;
                DEBUG("evt_cmd_complete %s ncmd=0x%02x",
                  ogf_ocf_name(hex_data, sizeof(hex_data), htobs(cc->opcode)), cc->ncmd);
            }
            break;

        case EVT_NUM_COMP_PKTS:
            if (data_len >= 1) {
                uint8_t i = 0, count = ((uint8_t *)data)[0];
                data++, len--;
                while (i < count && len >= 4) {
                    uint16_t handle = btohs(*(uint16_t *)data);
                    data += 2, len -= 2;
                    uint16_t completed = btohs(*(uint16_t *)data);
                    data += 2, len -= 2;
                    DEBUG("completed packet handle=%i count=%i", handle, completed);
                }
            }
            break;

        case EVT_DISCONN_COMPLETE:
            if (data_len >= sizeof(evt_disconn_complete)) {
                evt_disconn_complete *disconn = data;
                DEBUG("DISCONNECT hci_handle=%d status=0x%02x reason=0x%02x",
                    btohs(disconn->handle), disconn->status, disconn->reason);
                if (bhci->on_disconnect) bhci->on_disconnect(bhci, disconn, bhci->on_disconnect_arg);
            }
            break;

        case EVT_LE_META_EVENT:
            if (data_len > 0) {
                uint8_t le_event = *(uint8_t *)data;
                data++, data_len--;
                switch (le_event) {
                    case EVT_LE_CONN_COMPLETE:
                        if (data_len >= sizeof(evt_le_connection_complete)) {
                            evt_le_connection_complete *conn = data;
                            char addr[BT_ADDR_SIZE];
                            addr2str(&conn->peer_bdaddr, addr);
                            DEBUG("LE_CONNECT: addr=%s handle=%d", addr, btohs(conn->handle));
                            if (bhci->on_connect) bhci->on_connect(bhci, conn, addr, bhci->on_connect_arg);
                        }
                        break;

                    case EVT_LE_ADVERTISING_REPORT:
                        if (bhci->on_advertisement) bhci->on_advertisement(bhci, data, len, bhci->on_advertisement_arg);
                        break;

                    case EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE:
                        if (data_len >= sizeof(evt_le_read_remote_used_features_complete)) {
                            evt_le_read_remote_used_features_complete *feat = data;
                            DEBUG("connect complete status=0x%02x handle=%i", feat->status, btohs(feat->handle));
                        }
                        break;

                    default:
                        TRACE("hci %s", data2hex(hex_data, sizeof(hex_data), buffer, len));
                }
            }
            break;

        default:
            TRACE("hci %s", data2hex(hex_data, sizeof(hex_data), buffer, len));
            if (event == 0) {
                // linux bluetooth driver bug: seems to insert a zero byte when it loses sync.
                // this may be fixed in linux 4.4.
                ERROR("HCI driver lost sync!");
                if (bhci->on_desync) bhci->on_desync(bhci, bhci->on_desync_arg);
            }
    }
}
