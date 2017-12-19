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

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "beetle.h"
#include "babygatt_central.h"
#include "babygatt_common.h"
#include "connlist.h"
#include "log.h"
#include "utils.h"

#define PENDING_COMMAND_READ    0
#define PENDING_COMMAND_WRITE   1
#define PENDING_COMMAND_KAT     2

static int send_gap(conn_info_t *ci, int nparams, int cmd, int p1, int p2, int p3)
{
    uint8_t buf[7];
    char hexbuf[15];

    if (ci == NULL)
        return -1;

    buf[0] = cmd;
    buf[1] = p1 & 0xff;
    buf[2] = p1 >> 8;
    buf[3] = p2 & 0xff;
    buf[4] = p2 >> 8;
    buf[5] = p3 & 0xff;
    buf[6] = p3 >> 8;

    TRACE("l2s %04x %s", ci->l2cap_fd, data2hex(hexbuf, sizeof(hexbuf), buf, 1 + nparams * 2));
    return write(ci->l2cap_fd, buf, 1 + nparams * 2);
}

static int find_info (conn_info_t *ci, int handle)
{
    return send_gap(ci, 2, ATT_OP_FIND_INFO_REQ, handle, handle, 0);
}

static int read_by_type(conn_info_t *ci, int start, int end)
{
    return send_gap(ci, 3, ATT_OP_READ_BY_TYPE_REQ, start, end, GATT_CHARAC_UUID);
}



static kattribute_t *get_kattribute(conn_info_t *ci, int attr_id, int props)
{
    if (ci->num_attr != 0 && ci->attr_list[ci->num_attr - 1].attribute_id == attr_id) {
        return &ci->attr_list[ci->num_attr - 1];
    } else {
        if (ci->num_attr < (sizeof(ci->attr_list) / sizeof(kattribute_t)) - 1) {
            send_cmd("kat %04x %04x %04x %04x", ci->l2cap_fd, STATUS_OK, attr_id, props);
            ci->attr_list[ci->num_attr].attribute_id = attr_id;
            ci->num_attr++;
            return &ci->attr_list[ci->num_attr-1];
        } else {
            return NULL;
        }
    }
}

#define OTA_DFU_CONTROL_CHANNEL_KATTRIBUTE 0xFDFF
#define OTA_DFU_DATA_CHANNEL_KATTRIBUTE    0xFE00

static int on_read_by_type_resp(conn_info_t *ci, uint8_t *data, int len)
{
    int i;
    int n = data[1];
    int value_handle = 0xffff;

    for (i = 2; i < len; i += n) {

        int flags = data[i + 2];
        value_handle = data[i + 3] + (data[i + 4] << 8);

        if (n != 7) { // 16 byte UUID
            if (!memcmp(g_gattAferoUuidPreamble, data + i + 5, sizeof(g_gattAferoUuidPreamble)) &&
                data[i + 19] == 0x5a && data[i + 20] == 0x7a) { // kiban UUID

                int kattr_id = data[i+17] + ((data[i+18]) << 8);
                if (kattr_id < 0xC350) {
                    kattr_id &= 0x7FFF; // Old skool attribute with high bit set for write
                }

                kattribute_t *ka = get_kattribute(ci, kattr_id, flags);

                if (ka == NULL) {
                    return -1;
                }

                if (flags & (GATT_CHARACTERISTIC_WRITE_NO_RESPONSE | GATT_CHARACTERISTIC_WRITE)) {
                    ka->write_handle = value_handle;
                    ka->isNoResponse = ((flags & GATT_CHARACTERISTIC_WRITE_NO_RESPONSE) ? 1 : 0);
                } else {
                    ka->read_handle = value_handle;
                    if ((flags & GATT_CHARACTERISTIC_NOTIFY) || (flags & GATT_CHARACTERISTIC_INDICATE)) {
                        ka->isIndication = ((flags & GATT_CHARACTERISTIC_INDICATE) ? 1 : 0);
                        return find_info(ci, value_handle + 1); // find config descriptor
                    }
                }
            } else if (!memcmp(g_gattDfuUuidPreamble, data + i + 5, sizeof(g_gattDfuUuidPreamble)) &&
                data[i + 19] == 0x00 && data [i + 20] == 0x00) {
                int sub_uuid = data[i+17] + (data[i+18] << 8);
                int uuid = 0x1531 == sub_uuid ? OTA_DFU_CONTROL_CHANNEL_KATTRIBUTE : OTA_DFU_DATA_CHANNEL_KATTRIBUTE;
                kattribute_t *ka = get_kattribute(ci, uuid, flags); // temporary attribute ID for DFU

                if (ka == NULL) {
                    return -1;
                }

                switch (sub_uuid) {

                    case 0x1531 :
                        ka->write_handle = value_handle;
                        ka->read_handle = value_handle;
                        ka->isIndication = ((flags & GATT_CHARACTERISTIC_INDICATE) ? 1 : 0);
                        return find_info(ci, value_handle + 1) ; // find config descriptor
                    case 0x1532 :
                        ka->write_handle = value_handle;
                        break;
                    default :
                        break;
                }
            }
        }
    }

    if (value_handle != 0xffff) {
        read_by_type(ci, value_handle + 1, 0xffff);
    }

    return 0;
}


static int on_find_info_resp(conn_info_t *ci, uint8_t *data, int len)
{
    int format = data[1];

    int handle = data[2] + (data[3] << 8);
    if (format == ATT_UUID16_FORMAT) {
        switch (data[4] + (data[5] << 8)) {
            case GATT_PRIM_SVC_UUID :
            case GATT_CHARAC_UUID :
                return read_by_type(ci, handle, 0xffff);
            case GATT_CLIENT_CHARAC_CFG_UUID :
                ci->attr_list[ci->num_attr - 1].read_config_handle = handle;
                return read_by_type(ci, handle + 1, 0xffff);
                break;
            default :
                break;
        }
    }
    return find_info(ci, handle + 1);
}

int cmd_kattributes(void *param1, void *param2, void *param3, void *context)
{
    int l2cap_fd = *(int *)param1;
    conn_info_t *ci = cl_find_by_l2cap_fd(&l2cap_fd);
    if (ci == NULL) {
        send_cmd("kat %04x %04x %04x", l2cap_fd, STATUS_UNKNOWN_CONN, 0);
        return 0;
    }

    if (ci->flags & CONN_FLAGS_PENDING_OP) {
        send_cmd("kat %04x %04x %04x", l2cap_fd, STATUS_PENDING, 0);
        return 0;
    }

    if (ci->d_info->attributes != NULL) {
        DEBUG("about to free stale attributes for %s, ptr=%p", ci->d_info->addr, ci->d_info->attributes);
        free(ci->d_info->attributes);
        ci->d_info->attributes = NULL;
        DEBUG("stale attribute free was successful");
    }
    ci->flags |= CONN_FLAGS_PENDING_OP;
    ci->pend_cmd = PENDING_COMMAND_KAT;

    read_by_type(ci, 0x0001, 0xffff);
    return 0;
}

#define WRITE_COMMAND_SIZE 3
#define MAX_WRITE_PACKET_SIZE (DEFAULT_BLE_MTU - WRITE_COMMAND_SIZE)

int cmd_write(void *param1, void *param2, void *param3, void *context)
{
    int l2cap_fd = *(int *)param1;
    int kattr_id = *(int *)param2;

    conn_info_t *ci = cl_find_by_l2cap_fd(&l2cap_fd);
    if (ci == NULL) {
        send_cmd("wri %04x %04x %04x", l2cap_fd, kattr_id, STATUS_UNKNOWN_CONN);
        return 0;
    }

    if (ci->flags & CONN_FLAGS_PENDING_OP) {
        send_cmd("wri %04x %04x %04x", l2cap_fd, kattr_id, STATUS_PENDING);
        return 0;
    }

    kattribute_t *kattr = dl_find_attr(ci->d_info, kattr_id);
    if (kattr == NULL) {
        send_cmd("wri %04x %04x %04x", l2cap_fd, kattr_id, STATUS_UNKNOWN_ATTR);
        return 0;
    }

    if (kattr->write_handle == 0) {
        send_cmd("wri %04x %04x %04x", l2cap_fd, kattr_id, STATUS_NOT_PERMITTED);
        return 0;
    }

    ci->attr_id = kattr_id;

    uint8_t buf[DEFAULT_BLE_MTU];
    char dump[(MAX_WRITE_PACKET_SIZE + WRITE_COMMAND_SIZE) * 2 + 1];

    buf[0] = kattr->isNoResponse ? ATT_OP_WRITE_CMD : ATT_OP_WRITE_REQ;
    buf[1] = kattr->write_handle & 0xff;
    buf[2] = kattr->write_handle >> 8;

    int num_chars = hex2data(param3, buf + WRITE_COMMAND_SIZE, MAX_WRITE_PACKET_SIZE);
    TRACE("l2s %s", data2hex(dump, sizeof(dump), buf, num_chars + 3));

    if (write(ci->l2cap_fd, buf, num_chars + 3) < 0) {
        log_failure("cmd_write:write");
        send_cmd("wri %04x %04x %04x", ci->l2cap_fd, ci->attr_id, STATUS_IO_ERROR);
        return -1;
    }

    if (!kattr->isNoResponse) {
        ci->flags |= CONN_FLAGS_PENDING_OP;
        ci->pend_cmd = PENDING_COMMAND_WRITE;
    }
    return 0;
}

int cmd_read(void *param1, void *param2, void *param3, void *context)
{
    int l2cap_fd = *(int *)param1;
    int kattr_id = *(int *)param2;

    conn_info_t *ci = cl_find_by_l2cap_fd(&l2cap_fd);
    if (ci == NULL) {
        send_cmd("rea %04x %04x %04x", l2cap_fd, kattr_id, STATUS_UNKNOWN_CONN);
        return 0;
    }

    if (ci->flags & CONN_FLAGS_PENDING_OP) {
        send_cmd("rea %04x %04x %04x", l2cap_fd, kattr_id, STATUS_PENDING);
        return 0;
    }

    kattribute_t *kattr = dl_find_attr(ci->d_info, kattr_id);
    if (kattr == NULL) {
        send_cmd("rea %04x %04x %04x", l2cap_fd, kattr_id, STATUS_UNKNOWN_ATTR);
        return 0;
    }

    if (kattr->read_handle == 0 || kattr_id == 0xffff) {
        send_cmd("rea %04x %04x %04x", l2cap_fd, kattr_id, STATUS_NOT_PERMITTED);
        return 0;
    }

    if (send_gap(ci, 1, ATT_OP_READ_REQ, kattr->read_handle, 0, 0) < 0) {
        send_cmd("rea %04x %04x %04x", l2cap_fd, kattr_id, STATUS_IO_ERROR);
        return 0;
    }

    ci->flags |= CONN_FLAGS_PENDING_OP;
    ci->pend_cmd = PENDING_COMMAND_READ;
    ci->attr_id = kattr_id;

    return 0;
}

int cmd_notify_enable(void *param1, void *param2, void *param3, void *context)
{
    int l2cap_fd = *(int *)param1;
    int kattr_id = *(int *)param2;
    int value = *(int *)param3;
    int sendValue;

    conn_info_t *ci = cl_find_by_l2cap_fd(&l2cap_fd);
    if (ci == NULL) {
        send_cmd("nen %04x %04x %04x", l2cap_fd, kattr_id, STATUS_UNKNOWN_CONN);
        return 0;
    }

    if (ci->flags & CONN_FLAGS_PENDING_OP) {
        send_cmd("nen %04x %04x %04x", l2cap_fd, kattr_id, STATUS_PENDING);
        return 0;
    }

    kattribute_t *kattr = dl_find_attr(ci->d_info, kattr_id);
    if (kattr == NULL) {
        send_cmd("nen %04x %04x %04x", l2cap_fd, kattr_id, STATUS_UNKNOWN_ATTR);
        return 0;
    }

    if (kattr->read_config_handle == 0) {
        send_cmd("nen %04x %04x %04x", l2cap_fd, kattr_id, STATUS_NOT_PERMITTED);
        return 0;
    }

    sendValue = (value ? (kattr->isIndication ? 0x2 : 0x1) : 0x0);

    if (send_gap(ci, 2, ATT_OP_WRITE_CMD, kattr->read_config_handle, sendValue, 0) < 0) {
        /* seems like this happens sometimes if the socket is just... dead */
        log_failure("cmd_notify_enable");
        send_cmd("nen %04x %04x %04x", l2cap_fd, kattr_id, STATUS_IO_ERROR);
        shutdown(l2cap_fd, SHUT_WR);
        return 0;
    }

    /* reply immediately */
    send_cmd("nen %04x %04x %04x", l2cap_fd, kattr_id, STATUS_OK);
    return 0;
}

void gatt_fail_any_pending(conn_info_t *ci, int error_code) {
    if (ci->flags & CONN_FLAGS_PENDING_OP) {
        ci->flags &= ~CONN_FLAGS_PENDING_OP;
        switch (ci->pend_cmd) {
            case PENDING_COMMAND_WRITE :
                send_cmd("wri %04x %04x %04x", ci->l2cap_fd, ci->attr_id, error_code);
                break;
            case PENDING_COMMAND_READ :
                send_cmd("rea %04x %04x %04x", ci->l2cap_fd, ci->attr_id, error_code);
                break;
            default :
                break;
        }
    }
}

void on_central_data(conn_info_t *ci, uint8_t *data, int len)
{
    int opcode = data[0];

    switch (opcode) {
        case ATT_OP_ERROR: {
            switch (data[1]) {
                case ATT_OP_READ_BY_TYPE_REQ :
                case ATT_OP_FIND_INFO_REQ :
                {
                    /* Copy attribute list to the device_info structure */
                    /* The last entry in the list is marked with an attribute == 0 */
                    kattribute_t *new = (kattribute_t *)calloc(ci->num_attr + 1, sizeof(kattribute_t));
                    if (new == NULL) {
                        ERROR("can't allocate space for attributes");
                        return;
                    }

                    memcpy (new, ci->attr_list, ci->num_attr * sizeof(kattribute_t));
                    ci->d_info->attributes = new;

                    /* Print out the attribute list */
                    if (g_debugging >= DEBUG_ON) {
                        kattribute_t *ka = new;
                        while (ka->attribute_id != 0) {
                            DEBUG("attr %d w_handle=%d r_handle=%d rc_handle=%d",
                                ka->attribute_id, ka->write_handle, ka->read_handle, ka->read_config_handle);
                            ka++;
                        }
                    }

                    /* terminate the search */
                    send_cmd("kat %04x %04x %04x", ci->l2cap_fd, STATUS_OK, 0);
                    ci->flags &= ~CONN_FLAGS_PENDING_OP;
                }
                    break;
                default:
                    ERROR("error for op code %d, error code %d", data[1], data[4]);
                    gatt_fail_any_pending(ci, STATUS_BLUETOOTH_ERROR);
                    break;
            }
            break;
        }

        case ATT_OP_READ_BY_TYPE_RESP :
            on_read_by_type_resp(ci, data, len);
            break;

        case ATT_OP_FIND_INFO_RESP :
            on_find_info_resp(ci, data, len);
            break;

        case ATT_OP_WRITE_RESP :
            if (ci->flags & CONN_FLAGS_PENDING_OP) {
                ci->flags &= ~CONN_FLAGS_PENDING_OP;
                send_cmd("wri %04x %04x %04x", ci->l2cap_fd, ci->attr_id, STATUS_OK);
            }
            break;

        case ATT_OP_READ_RESP: {
            char buf[MAX_PACKET_SIZE * 2 + 1];
            data2hex(buf, sizeof(buf), data + 1, len-1);
            ci->flags &= ~CONN_FLAGS_PENDING_OP;
            send_cmd("rea %04x %04x %04x %s", ci->l2cap_fd, ci->attr_id, STATUS_OK, buf);
            break;
        }

        case ATT_OP_HANDLE_NOTIFY :
        case ATT_OP_HANDLE_IND :
        {
            int handle = data[1] + (data[2] << 8);
            if (ci->d_info) {
                kattribute_t *ka = ci->d_info->attributes;
                if (ka) {
                    while (ka->attribute_id) {
                        if (ka->read_handle == handle) {
                            char buf[MAX_PACKET_SIZE * 2 + 1];
                            data2hex(buf, sizeof(buf), data+3, len-3);
                            if (ka->isIndication) {
                                send_gap(ci, 0, ATT_OP_HANDLE_CNF, handle, 0, 0); // Attempt to confirm; should probably retry
                            }

                            send_cmd("not %04x %04x %s", ci->l2cap_fd, ka->attribute_id, buf);
                            return;
                        }
                        ka++;
                    }
                }
            }
            ERROR("unknown attribute for c_handle %d and handle %d", ci->l2cap_fd, handle);
            break;
        }

        default :
            break;
    }
}
