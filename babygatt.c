/********************************************************************************
 *
 * Copyright (c) 2016 Afero, Inc.
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
#include <syslog.h>
#include <unistd.h>

#include "beetle.h"
#include "connlist.h"
#include "babygatt.h"
#include "utils.h"

extern int g_debug;

#define ATT_OP_ERROR                0x01
#define ATT_OP_FIND_INFO_REQ        0x04
#define ATT_OP_FIND_INFO_RESP       0x05
#define ATT_OP_READ_BY_TYPE_REQ     0x08
#define ATT_OP_READ_BY_TYPE_RESP    0x09
#define ATT_OP_READ_REQ             0x0A
#define ATT_OP_READ_RESP            0x0B
#define ATT_OP_WRITE_REQ            0x12
#define ATT_OP_WRITE_RESP           0x13
#define ATT_OP_WRITE_CMD            0x52
#define ATT_OP_HANDLE_NOTIFY        0x1B
#define ATT_OP_HANDLE_IND           0x1D
#define ATT_OP_HANDLE_CNF           0x1E

#define GATT_PRIM_SVC_UUID              0x2800
#define GATT_CHARAC_UUID                0x2803
#define GATT_CLIENT_CHARAC_CFG_UUID     0x2902

#define PENDING_COMMAND_READ    0
#define PENDING_COMMAND_WRITE   1
#define PENDING_COMMAND_KAT     2

#define MAX_WRITE_PACKET_SIZE 20

static const uint8_t kiban_uuid_le_preamble[] = { 0x6b, 0x69, 0x62, 0x61, 0x6e, 0x42, 0x4c, 0x45, 0x75, 0x75, 0x69, 0x64 };
static const uint8_t dfu_uuid_le_preamble[] =   { 0x23, 0xd1, 0xbc, 0xea, 0x5f, 0x78, 0x23, 0x15, 0xde, 0xef, 0x12, 0x12 };

static int send_gap(conn_info_t *ci, int nparams, int cmd, int p1, int p2, int p3)
{
    uint8_t buf[7];

    if (ci == NULL)
        return -1;

    buf[0] = cmd;
    buf[1] = p1 & 0xff;
    buf[2] = p1 >> 8;
    buf[3] = p2 & 0xff;
    buf[4] = p2 >> 8;
    buf[5] = p3 & 0xff;
    buf[6] = p3 >> 8;

    if (g_debug >= 2) {
        int i;
        char hexbuf[15];
        for (i = 0; i < 1 + nparams * 2; i++) {
            sprintf (hexbuf + i*2, "%02x", buf[i]);
        }
        syslog(LOG_DEBUG,"l2s %04x %s", ci->l2cap_fd, hexbuf);
    }

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


#define CHARACTERISTIC_WRITE_CMD          0x04
#define CHARACTERISTIC_WRITE_REQ          0x08
#define CHARACTERISTIC_BROADCAST          0x01
#define CHARACTERISTIC_READ               0x02
#define CHARACTERISTIC_WRITE_NO_RESPONSE  0x04
#define CHARACTERISTIC_WRITE              0x08
#define CHARACTERISTIC_NOTIFY             0x10
#define CHARACTERISTIC_INDICATE           0x20
#define CHARACTERISTIC_SIGNED_WRITES      0x40
#define CHARACTERISTIC_EXTENDED_PROPS     0x80

// This is copied verbatim from the other repo since we don't share stuff between the two
enum CharacteristicProperty {
    CharacteristicProperty_None            = 0x00,
    CharacteristicProperty_Broadcast       = 0x01,
    CharacteristicProperty_Read            = 0x02,
    CharacteristicProperty_WriteNoResponse = 0x04,
    CharacteristicProperty_Write           = 0x08,
    CharacteristicProperty_Notify          = 0x10,
    CharacteristicProperty_Indicate        = 0x20,
    CharacteristicProperty_SignedWrites    = 0x40,
    CharacteristicProperty_ExtendedProps   = 0x80
};

static uint32_t ConvertToCharacteristicProperty(int nativeProps) {
    uint32_t props = CharacteristicProperty_None;
    if (nativeProps & CHARACTERISTIC_BROADCAST) {
        props = props | CharacteristicProperty_Broadcast;
    }
    if (nativeProps & CHARACTERISTIC_READ) {
        props = props | CharacteristicProperty_Read;
    }
    if (nativeProps & CHARACTERISTIC_WRITE_NO_RESPONSE) {
        props = props | CharacteristicProperty_WriteNoResponse;
    }
    if (nativeProps & CHARACTERISTIC_WRITE) {
        props = props | CharacteristicProperty_Write;
    }
    if (nativeProps & CHARACTERISTIC_NOTIFY) {
        props = props | CharacteristicProperty_Notify;
    }
    if (nativeProps & CHARACTERISTIC_INDICATE) {
        props = props | CharacteristicProperty_Indicate;
    }
    if (nativeProps & CHARACTERISTIC_SIGNED_WRITES) {
        props = props | CharacteristicProperty_SignedWrites;
    }
    if (nativeProps & CHARACTERISTIC_EXTENDED_PROPS) {
        props = props | CharacteristicProperty_ExtendedProps;
    }

    return props;
}

static kattribute_t *get_kattribute(conn_info_t *ci, int attr_id, int props)
{
    if (ci->num_attr != 0 && ci->attr_list[ci->num_attr - 1].attribute_id == attr_id) {
        return &ci->attr_list[ci->num_attr - 1];
    } else {
        if (ci->num_attr < (sizeof(ci->attr_list) / sizeof(kattribute_t)) - 1) {
            send_cmd("kat %04x %04x %04x %04x", ci->l2cap_fd, STATUS_OK, attr_id, ConvertToCharacteristicProperty(props));
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
            if (!memcmp(kiban_uuid_le_preamble, data + i + 5, sizeof(kiban_uuid_le_preamble)) &&
                data[i + 19] == 0x5a && data[i + 20] == 0x7a) { // kiban UUID

                int kattr_id = data[i+17] + ((data[i+18]) << 8);
                if (kattr_id < 0xC350) {
                    kattr_id &= 0x7FFF; // Old skool attribute with high bit set for write
                }

                kattribute_t *ka = get_kattribute(ci, kattr_id, flags);

                if (ka == NULL) {
                    return -1;
                }

                if (flags & (CHARACTERISTIC_WRITE_CMD | CHARACTERISTIC_WRITE_REQ)) {
                    ka->write_handle = value_handle;
                    ka->isNoResponse = ((flags & CHARACTERISTIC_WRITE_NO_RESPONSE) ? 1 : 0);
                } else {
                    ka->read_handle = value_handle;
                    if ((flags & CHARACTERISTIC_NOTIFY) || (flags & CHARACTERISTIC_INDICATE)) {
                        ka->isIndication = ((flags & CHARACTERISTIC_INDICATE) ? 1 : 0);
                        return find_info(ci, value_handle + 1); // find config descriptor
                    }
                }
            } else if (!memcmp(dfu_uuid_le_preamble, data + i + 5, sizeof(dfu_uuid_le_preamble)) &&
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
                        ka->isIndication = ((flags & CHARACTERISTIC_INDICATE) ? 1 : 0);
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
    int n = data[1];    // 1? not sure what that is (1 normally)

    int handle = data[2] + (data[3] << 8);
    if (n == 1) {
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

int cmd_kattributes(void *param1, void *param2, void *param3)
{
    int l2cap_fd = *(int *)param1;
    conn_info_t *ci = cl_find_by_l2cap_fd(&l2cap_fd);
    if (ci == NULL) {
        send_cmd("kat %04x %04x %04x", l2cap_fd, STATUS_UNKNOWN_CONN, 0);
        return -1;
    }

    if (ci->flags & CONN_FLAGS_PENDING_OP) {
        send_cmd("kat %04x %04x %04x", l2cap_fd, STATUS_PENDING, 0);
        return -1;
    }

    if (ci->d_info->attributes != NULL) {
        free(ci->d_info->attributes);
        ci->d_info->attributes = NULL;
    }
    ci->flags |= CONN_FLAGS_PENDING_OP;
    ci->pend_cmd = PENDING_COMMAND_KAT;

    return read_by_type(ci, 0x0001, 0xffff);
}

#define WRITE_COMMAND_SIZE 3

static int write_packet(conn_info_t *ci)
{
    char buf[MAX_WRITE_PACKET_SIZE + WRITE_COMMAND_SIZE];
    int num_chars;

    kattribute_t *kattr = dl_find_attr(ci->d_info, ci->attr_id);
    buf[0] = kattr->isNoResponse ? ATT_OP_WRITE_CMD : ATT_OP_WRITE_REQ;
    buf[1] = kattr->write_handle & 0xff;
    buf[2] = kattr->write_handle >> 8;

    // if finished send success story to sender
    if (ci->write_pos >= ci->write_len) {
        ci->flags &= ~CONN_FLAGS_PENDING_OP;
        send_cmd("wri %04x %04x %04x", ci->l2cap_fd, ci->attr_id, STATUS_OK);
        return 0;
    }

    num_chars = ci->write_len - ci->write_pos;
    if (num_chars > MAX_WRITE_PACKET_SIZE)
        num_chars = MAX_WRITE_PACKET_SIZE;

    memcpy(buf + WRITE_COMMAND_SIZE, ci->write_buf + ci->write_pos, num_chars);

    if (g_debug >= 2) {
        char dump[(MAX_WRITE_PACKET_SIZE + WRITE_COMMAND_SIZE) * 2 + 1];
        int i;
        for (i = 0; i < num_chars + 3; i++)
            sprintf(&dump[i*2],"%02x",buf[i]);
        syslog(LOG_DEBUG, "l2s %s", dump);
    }

    if (write(ci->l2cap_fd, buf, num_chars + 3) < 0) {
        syslog(LOG_ERR,"cmd_write:i/o error:%s", strerror(errno));
        send_cmd("wri %04x %04x %04x", ci->l2cap_fd, ci->attr_id, STATUS_IO_ERROR);
        return -1;
    }

    // Write successful so increment position
    ci->write_pos += num_chars;

    if (!kattr->isNoResponse) {
    	ci->flags |= CONN_FLAGS_PENDING_OP;
    	ci->pend_cmd = PENDING_COMMAND_WRITE;
    }
    return 0;
}

int cmd_write(void *param1, void *param2, void *param3)
{
    int l2cap_fd = *(int *)param1;
    int kattr_id = *(int *)param2;

    conn_info_t *ci = cl_find_by_l2cap_fd(&l2cap_fd);
    if (ci == NULL) {
        send_cmd("wri %04x %04x %04x", l2cap_fd, kattr_id, STATUS_UNKNOWN_CONN);
        return -1;
    }

    if (ci->flags & CONN_FLAGS_PENDING_OP) {
        send_cmd("wri %04x %04x %04x", l2cap_fd, kattr_id, STATUS_PENDING);
        return -1;
    }

    kattribute_t *kattr = dl_find_attr(ci->d_info, kattr_id);
    if (kattr == NULL) {
        send_cmd("wri %04x %04x %04x", l2cap_fd, kattr_id, STATUS_UNKNOWN_ATTR);
        return -1;
    }

    if (kattr->write_handle == 0) {
        send_cmd("wri %04x %04x %04x", l2cap_fd, kattr_id, STATUS_NOT_PERMITTED);
        return -1;
    }

    ci->attr_id = kattr_id;
    ci->write_len = hex2data((char *)param3, ci->write_buf, CONN_WRITE_BUF_SIZE);
    ci->write_pos = 0;

    return write_packet(ci);
}

int cmd_read(void *param1, void *param2, void *param3)
{
    int l2cap_fd = *(int *)param1;
    int kattr_id = *(int *)param2;

    conn_info_t *ci = cl_find_by_l2cap_fd(&l2cap_fd);
    if (ci == NULL) {
        send_cmd("rea %04x %04x %04x", l2cap_fd, kattr_id, STATUS_UNKNOWN_CONN);
        return -1;
    }

    if (ci->flags & CONN_FLAGS_PENDING_OP) {
        send_cmd("rea %04x %04x %04x", l2cap_fd, kattr_id, STATUS_PENDING);
        return -1;
    }

    kattribute_t *kattr = dl_find_attr(ci->d_info, kattr_id);
    if (kattr == NULL) {
        send_cmd("rea %04x %04x %04x", l2cap_fd, kattr_id, STATUS_UNKNOWN_ATTR);
        return -1;
    }

    if (kattr->read_handle == 0 || kattr_id == 0xffff) {
        send_cmd("rea %04x %04x %04x", l2cap_fd, kattr_id, STATUS_NOT_PERMITTED);
        return -1;
    }

    if (send_gap(ci, 1, ATT_OP_READ_REQ, kattr->read_handle, 0, 0) < 0) {
        send_cmd("rea %04x %04x %04x", l2cap_fd, kattr_id, STATUS_IO_ERROR);
        return -1;
    }

    ci->flags |= CONN_FLAGS_PENDING_OP;
    ci->pend_cmd = PENDING_COMMAND_READ;
    ci->attr_id = kattr_id;

    return 0;
}

int cmd_notify_enable(void *param1, void *param2, void *param3)
{
    int l2cap_fd = *(int *)param1;
    int kattr_id = *(int *)param2;
    int value = *(int *)param3;
    int sendValue;

    conn_info_t *ci = cl_find_by_l2cap_fd(&l2cap_fd);
    if (ci == NULL) {
        send_cmd("nen %04x %04x %04x", l2cap_fd, kattr_id, STATUS_UNKNOWN_CONN);
        return -1;
    }

    if (ci->flags & CONN_FLAGS_PENDING_OP) {
        send_cmd("nen %04x %04x %04x", l2cap_fd, kattr_id, STATUS_PENDING);
        return -1;
    }

    kattribute_t *kattr = dl_find_attr(ci->d_info, kattr_id);
    if (kattr == NULL) {
        send_cmd("nen %04x %04x %04x", l2cap_fd, kattr_id, STATUS_UNKNOWN_ATTR);
        return -1;
    }

    if (kattr->read_config_handle == 0) {
        send_cmd("nen %04x %04x %04x", l2cap_fd, kattr_id, STATUS_NOT_PERMITTED);
        return -1;
    }

    sendValue = (value ? (kattr->isIndication ? 0x2 : 0x1) : 0x0);

    if (send_gap(ci, 2, ATT_OP_WRITE_CMD, kattr->read_config_handle, sendValue, 0) < 0) {
        syslog(LOG_ERR,"cmd_notify_enable:i/o error:%s", strerror(errno));
        send_cmd("nen %04x %04x %04x", l2cap_fd, kattr_id, STATUS_IO_ERROR);
        return -1;
    }

    /* reply immediately */
    send_cmd("nen %04x %04x %04x", l2cap_fd, kattr_id, STATUS_OK);
    return 0;
}

int on_data(conn_info_t *ci, uint8_t *data, int len)
{
    int opcode = data[0];

    switch (opcode) {
        case ATT_OP_ERROR :
        {
            switch (data[1]) {
                case ATT_OP_READ_BY_TYPE_REQ :
                case ATT_OP_FIND_INFO_REQ :
                {
                    /* Copy attribute list to the device_info structure */
                    /* The last entry in the list is marked with an attribute == 0 */
                    kattribute_t *new = (kattribute_t *)calloc(ci->num_attr + 1, sizeof(kattribute_t));
                    if (new == NULL) {
                        syslog(LOG_ERR, "can't allocate space for attributes");
                        return -1;
                    }

                    memcpy (new, ci->attr_list, ci->num_attr * sizeof(kattribute_t));
                    ci->d_info->attributes = new;

                    /* Print out the attribute list */
                    if (g_debug >= 1) {
                        kattribute_t *ka = new;
                        while (ka->attribute_id != 0) {
                            syslog(LOG_DEBUG,"attr %d w_handle=%d r_handle=%d rc_handle=%d",
                                   ka->attribute_id, ka->write_handle, ka->read_handle, ka->read_config_handle);
                            ka++;
                        }
                    }

                    /* terminate the search */
                    send_cmd("kat %04x %04x %04x", ci->l2cap_fd, STATUS_OK, 0);
                    ci->flags &= ~CONN_FLAGS_PENDING_OP;
                }
                    break;
                default :
                    if (ci->flags & CONN_FLAGS_PENDING_OP) {
                        syslog(LOG_ERR, "error for op code %d, error code %d", data[1], data[4]);
                        switch (ci->pend_cmd) {
                            case PENDING_COMMAND_WRITE :
                                send_cmd("wri %04x %04x %04x", ci->l2cap_fd, ci->attr_id, STATUS_BLUETOOTH_ERROR);
                                break;
                            case PENDING_COMMAND_READ :
                                send_cmd("rea %04x %04x %04x", ci->l2cap_fd, ci->attr_id, STATUS_BLUETOOTH_ERROR);
                                break;
                            default :
                                break;
                        }
                    }
                    break;
            }
        }
            break;

        case ATT_OP_READ_BY_TYPE_RESP :
            on_read_by_type_resp(ci, data, len);
            break;

        case ATT_OP_FIND_INFO_RESP :
            on_find_info_resp(ci, data, len);
            break;

        case ATT_OP_WRITE_RESP :
            write_packet(ci);
            break;

        case ATT_OP_READ_RESP :
        {
            char buf[1024];
            data2hex(buf, sizeof(buf), data + 1, len-1);
            ci->flags &= ~CONN_FLAGS_PENDING_OP;
            return send_cmd("rea %04x %04x %04x %s", ci->l2cap_fd, ci->attr_id, STATUS_OK, buf);
        }
            break;

        case ATT_OP_HANDLE_NOTIFY :
        case ATT_OP_HANDLE_IND :
        {
            int handle = data[1] + (data[2] << 8);
            if (ci->d_info) {
                kattribute_t *ka = ci->d_info->attributes;
                if (ka) {
                    while (ka->attribute_id) {
                        if (ka->read_handle == handle) {
                            char buf[1024];
                            data2hex(buf, sizeof(buf), data+3, len-3);
                            if (ka->isIndication) {
                                send_gap(ci, 0, ATT_OP_HANDLE_CNF, handle, 0, 0); // Attempt to confirm; should probably retry
                            }

                            return send_cmd("not %04x %04x %s", ci->l2cap_fd, ka->attribute_id, buf);
                        }
                        ka++;
                    }
                }
            }
            syslog(LOG_ERR,"unknown attribute for c_handle %d and handle %d", ci->l2cap_fd, handle);
        }
            break;

        default :
            break;
    }
    return 0;
}


