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
#include <stdint.h>

#include "beetle.h"
#include "babygatt_peripheral.h"
#include "babygatt_common.h"
#include "log.h"
#include "peripheral.h"
#include "utils.h"

extern int g_debug;

struct gap_entry {
    uint16_t uuid;
    uint16_t handle;
    uint8_t flags;
    uint16_t value;  /* used for characteristic config */
};

#define MAX_GAP_ATTRIBUTES 40
struct gap_entry s_attributes[MAX_GAP_ATTRIBUTES];

typedef enum {
    ATTR_SETUP_STATE_INITIAL = 0,
    ATTR_SETUP_STATE_IN_PROGRESS = 1,
    ATTR_SETUP_STATE_SET_UP = 2
} attr_setup_state_t;

static attr_setup_state_t s_attributeSetUpState = ATTR_SETUP_STATE_INITIAL;
static int s_numAttributes = 0;

static int add_attribute(uint16_t uuid, uint8_t flags)
{
    DEBUG("add_attribute: uuid=%x, flags=%d\n", uuid, flags);
    if (s_numAttributes >= MAX_GAP_ATTRIBUTES) {
        return -1;
    }
    s_attributes[s_numAttributes].handle = s_numAttributes + 1;
    s_attributes[s_numAttributes].uuid = uuid;
    s_attributes[s_numAttributes].flags = flags;
    s_numAttributes++;
    return 0;
}

static int per_send(int fd, uint8_t *data, int len)
{
    char buf[1024];
    DEBUG("peripheral_send: data=%s", data2hex(buf, sizeof(buf), data, len));
    return write(fd, data, len);
}

int cmd_per_kattribute(void *param1, void *param2, void *param3, void *data)
{
    uint16_t kattr = (uint16_t)*(int *)param1;
    uint8_t flags = (uint8_t)*(int *)param2;

    /* close things up if this is the last attribute */
    if (kattr == 0) { /* last attribute */
        s_attributeSetUpState = ATTR_SETUP_STATE_SET_UP;
        send_cmd("pka %04x %04x %04x", kattr, flags, STATUS_OK);
        return 0;
    }

    /* add the primary service if it doesn't exist */
    if (s_attributeSetUpState == ATTR_SETUP_STATE_INITIAL || s_attributeSetUpState == ATTR_SETUP_STATE_SET_UP) {
        s_numAttributes = 0;
        s_attributeSetUpState = ATTR_SETUP_STATE_IN_PROGRESS;
        add_attribute(GATT_PRIM_SVC_UUID, 0);
    }

    /* add the flags attribute */
    if (add_attribute(GATT_CHARAC_UUID, flags) < 0) {
        send_cmd("pka %04x %04x %04x", kattr, flags, STATUS_DATABASE_FULL);
        return 0;
    }

    /* add the value attribute */
    if (add_attribute(kattr, flags) < 0) {
        send_cmd("pka %04x %04x %04x", kattr, flags, STATUS_DATABASE_FULL);
        return 0;
    }

    /* add the control attribute if necessary */
    if (flags & (GATT_CHARACTERISTIC_NOTIFY | GATT_CHARACTERISTIC_INDICATE)) {
        if (add_attribute(GATT_CLIENT_CHARAC_CFG_UUID, flags) < 0) {
            send_cmd("pka %04x %04x %04x", kattr, flags, STATUS_DATABASE_FULL);
            return 0;
        }
    }

    send_cmd("pka %04x %04x %04x", kattr, flags, STATUS_OK);
    return 0;
}

static inline int uuid_size(uint16_t uuid)
{
    return (uuid >= GATT_PRIM_SVC_UUID && uuid <= GATT_CLIENT_CHARAC_CFG_UUID ? 2 : 16);
}

/* returns the number of bytes copied */
static int copy_to_packet(uint8_t *packet, int pos, uint8_t *data, int dataLen)
{
    DEBUG("copy_to_packet packet=%p, pos=%d data=%p, dataLen=%d", packet, pos, data, dataLen);
    if (pos + dataLen > DEFAULT_BLE_MTU) {
        return -1;
    }

    memcpy(packet + pos, data, dataLen);
    return pos + dataLen;
}

static void construct_uuid(uint8_t *buf, uint16_t uuid)
{
    DEBUG("construct_uuid: uuid=%d", uuid);
    if (uuid_size(uuid) == 2) {
        buf[0] = uuid & 0xff;
        buf[1] = uuid >> 8;
    } else {
        memcpy(buf, g_gattAferoUuidPreamble, sizeof(g_gattAferoUuidPreamble));
        buf[12] = uuid & 0xff;
        buf[13] = uuid >> 8;
        buf[14] = 0x5a;
        buf[15] = 0x7a;
    }
}

int check_start_end(int start, int end)
{
    if (start == 0 || start > end) {
        return -1;
    } else {
        return 0;
    }
}

#define ERROR_PACKET_SIZE 5
void per_send_err(int fd, uint8_t opcode, uint16_t handle, uint8_t reason)
{
    uint8_t buf[ERROR_PACKET_SIZE];
    buf[0] = ATT_OP_ERROR;
    buf[1] = opcode;
    buf[2] = handle & 0xff;
    buf[3] = handle >> 8;
    buf[4] = reason;
    per_send(fd, buf, sizeof(buf));
}

void per_do_find_info(int fd, int start, int end)
{
    uint8_t buf[MAX_PACKET_SIZE];
    int len = 0;

    /* send error back if out of range */
    if (start > s_numAttributes) {
        per_send_err(fd, ATT_OP_FIND_INFO_REQ, start, ATT_ERROR_ATTRIBUTE_NOT_FOUND);
        return;
    }

    /* translate to db index */
    start--; end--;

    buf[len++] = ATT_OP_FIND_INFO_RESP;
    int pktUuidSize = uuid_size(s_attributes[start].uuid);
    buf[len++] = (pktUuidSize == 2 ? ATT_UUID16_FORMAT : ATT_UUID128_FORMAT);

    while (start <= end && start < s_numAttributes) {
        uint8_t uuidEntry[2 + 16]; // size of return value
        uint16_t uuid = s_attributes[start].uuid;
        int uuidSize = uuid_size(uuid);

        /* All UUIDs need to be in the same format */
        if (uuidSize != pktUuidSize) {
            break;
        }

        /* create the new handle/uuid pair */
        uuidEntry[0] = s_attributes[start].handle % 0xff;
        uuidEntry[1] = s_attributes[start].handle >> 8;
        construct_uuid(uuidEntry + 2, uuid);
        /* add it to the packet if possible */
        int newLen = copy_to_packet(buf, len, uuidEntry, uuidSize + 2);

        if (newLen < 0) { /* not enough space for the new UUID */
            break;
        }

        len = newLen;
        start++;
    }

    per_send(fd, buf, len);
}

void per_do_read_by_type(int fd, int start, int end, uint16_t uuid)
{
    int i, valueLen = 0, len = 0;
    if (start > s_numAttributes) {
        per_send_err(fd, ATT_OP_READ_BY_TYPE_REQ, start, ATT_ERROR_ATTRIBUTE_NOT_FOUND);
        return;
    }

    /* translate to db index */
    start--; end--;
    uint8_t pktBuf[MAX_PACKET_SIZE];

    pktBuf[len++] = ATT_OP_READ_BY_TYPE_RESP;

    for (i = start; i <= end && i < s_numAttributes; i++) {
        if (s_attributes[i].uuid == uuid) {
            uint16_t handle = s_attributes[i].handle;
            if (uuid == GATT_CHARAC_UUID) {
                uint16_t charUuid = s_attributes[i+1].uuid;
                if (valueLen == 0) {
                    valueLen = 5 + uuid_size(charUuid);
                    pktBuf[len++] = valueLen;
                }
                if (valueLen != uuid_size(charUuid) + 5) {
                    break;
                }
                uint8_t buf[2 + 1 + 2 + 16];
                buf[0] = handle & 0xff;
                buf[1] = handle >> 8;
                buf[2] = s_attributes[i].flags;
                buf[3] = (handle + 1) & 0xff;
                buf[4] = (handle + 1) >> 8;
                construct_uuid(&buf[5], charUuid);
                int newLen = copy_to_packet(pktBuf, len, buf, valueLen);
                if (newLen < 0) {
                    break;
                } else {
                    len = newLen;
                }
            } else if (uuid == GATT_CLIENT_CHARAC_CFG_UUID) {
                if (valueLen == 0) {
                    valueLen = 3;
                    pktBuf[len++] = valueLen;
                }
                uint8_t buf[2 + 1];
                buf[0] = handle & 0xff;
                buf[1] = handle >> 8;
                buf[2] = s_attributes[i].flags;
                int newLen = copy_to_packet(pktBuf, len, buf, valueLen);
                if (newLen < 0) {
                    break;
                } else {
                    len = newLen;
                }
            } else if (uuid == GATT_PRIM_SVC_UUID) { /* we only have the Kiban primary service */
                if (valueLen == 0) {
                    valueLen = 18;
                    pktBuf[len++] = valueLen;
                }
                uint8_t buf[18];
                buf[0] = handle & 0xff;
                buf[1] = handle >> 8;
                int newLen = copy_to_packet(pktBuf, len, buf, valueLen);
                if (newLen < 0) {
                    break;
                } else {
                    len = newLen;
                }
            } else { /* this is reading the value of the characteristic */
                if (valueLen == 0) {
                    valueLen = 3;
                    pktBuf[len++] = valueLen;
                }
                uint8_t buf[2 + 1];
                buf[0] = handle & 0xff;
                buf[1] = handle >> 8;
                buf[2] = 0; /* return a value of zero if someone asks for the characteristic value */
                int newLen = copy_to_packet(pktBuf, len, buf, valueLen);
                if (newLen < 0) {
                    break;
                } else {
                    len = newLen;
                }
            }
        }
    }
    if (len < 3) {
        per_send_err(fd, ATT_OP_READ_BY_TYPE_REQ, start + 1, ATT_ERROR_ATTRIBUTE_NOT_FOUND);
    } else {
        per_send(fd, pktBuf, len);
    }
}

uint16_t s_indicationUuid = 0;

int cmd_per_indicate(void *param1, void *param2, void *param3, void *data)
{
    uint16_t uuid = (uint16_t)*(int *)param1;
    uint8_t buf[MAX_PACKET_SIZE];
    int len = hex2data(param2, buf + 3, sizeof(buf) - 3) + 3;
    struct peripheral_context *context = data;

    if (context->connection_fd < 0) {
        send_cmd("pin %04x %04x", uuid, STATUS_NOT_CONNECTED);
        return 0;
    }

    int i;
    for (i = 0; i < s_numAttributes; i++) {
        if (s_attributes[i].uuid == uuid) {
            uint16_t handle = s_attributes[i].handle;
            buf[0] = ATT_OP_HANDLE_IND;
            buf[1] = handle & 0xff;
            buf[2] = handle >> 8;
            s_indicationUuid = uuid;
            per_send(context->connection_fd, buf, len);
            break;
        }
    }
    return 0;
}

void per_do_write(int fd, uint16_t handle, uint8_t *data, int len, uint8_t cmd)
{
    struct gap_entry *gap = &s_attributes[handle - 1];
    uint16_t uuid = gap->uuid;
    uint8_t flags = gap->flags;

    DEBUG("per_do_write: handle=%d,uuid=%x,flags=%x", handle, uuid, flags);

    if (uuid == GATT_CLIENT_CHARAC_CFG_UUID) {
        if (len == 2) {
            uint16_t config = data[0] + (data[1] << 8);
            if (handle > 1) {
                /* characteristic uuid is the previous attribute */
                uint16_t charUuid = s_attributes[handle - 2].uuid;
                /* we don't support both notifications and indications */
                if (flags & GATT_CHARACTERISTIC_NOTIFY) {
                    send_cmd("pne %04x %04x", charUuid, (config & 0x1) ? 1 : 0);
                } else if (flags & GATT_CHARACTERISTIC_INDICATE) {
                    send_cmd("pne %04x %04x", charUuid, (config & 0x2) ? 1 : 0);
                }
                /* immediately respond to write */
                if (cmd == ATT_OP_WRITE_REQ) {
                    uint8_t response = ATT_OP_WRITE_RESP;
                    per_send(fd, &response, sizeof(response));
                }
            } else {
                ERROR("bad attribute database handle=%d", handle);
            }
        } else {
            if (cmd != ATT_OP_WRITE_CMD) {
                per_send_err(fd, cmd, handle, ATT_ERROR_INVALID_PDU);
                return;
            }
        }
    } else if (uuid != GATT_PRIM_SVC_UUID &&
        ((cmd == ATT_OP_WRITE_CMD && (flags & GATT_CHARACTERISTIC_WRITE_NO_RESPONSE)) ||
        (cmd == ATT_OP_WRITE_REQ && (flags & GATT_CHARACTERISTIC_WRITE)))) {
        char buf[MAX_PACKET_SIZE * 2 + 1];
        data2hex(buf, sizeof(buf), data, len);
        send_cmd("pwr %04x %s", uuid, buf);

        /* immediately send response */
        if (cmd == ATT_OP_WRITE_REQ) {
            uint8_t response = ATT_OP_WRITE_RESP;
            per_send(fd, &response, sizeof(response));
        }
    } else {
        if (cmd != ATT_OP_WRITE_CMD) {
            per_send_err(fd, cmd, handle, ATT_ERROR_WRITE_NOT_PERMITTED);
        }
    }
}


void on_peripheral_data(uint8_t *data, ssize_t len, int fd)
{
    char buf[1024];
    data2hex(buf, sizeof(buf), data, len);
    DEBUG("on_peripheral_data:data=%s", buf);

    if (s_attributeSetUpState != ATTR_SETUP_STATE_SET_UP) {
        WARNING("Attributes have not been set up: attributeSetUpState=%d", s_attributeSetUpState);
    }

    if (len < 1) {
        return;
    }

    int cmd = data[0];

    switch(cmd) {
        case ATT_OP_FIND_INFO_REQ :
            if (len == 5) {
                int start = data[1] + (data[2] << 8);
                int end = data[3] + (data[4] << 8);
                if (check_start_end(start, end) != 0) {
                    per_send_err(fd, ATT_OP_FIND_INFO_REQ, start, ATT_ERROR_INVALID_HANDLE);
                    break;
                }
                DEBUG("find_info start=%d end=%d", start, end);
                per_do_find_info(fd, start, end);
            } else {
                per_send_err(fd, ATT_OP_READ_BY_TYPE_REQ, 0, ATT_ERROR_INVALID_PDU);
            }
            break;
        case ATT_OP_READ_BY_TYPE_REQ :
            if (len >= 5) {
                int start = data[1] + (data[2] << 8);
                int end = data[3] + (data[4] << 8);
                if (check_start_end(start, end) != 0) {
                    per_send_err(fd, ATT_OP_READ_BY_TYPE_REQ, start, ATT_ERROR_INVALID_HANDLE);
                    break;
                }
                if (len == 7) {
                    uint16_t uuid = data[5] + (data[6] << 8);
                    DEBUG("read_by_type start=%d end=%d uuid=%d", start, end, uuid);
                    per_do_read_by_type(fd, start, end, uuid);
                } else if (len == 21) {
                    if (!memcmp(&data[5], g_gattAferoUuidPreamble, sizeof(g_gattAferoUuidPreamble)) &&
                        data[19] == 0x5a &&
                        data[20] == 0x7a) {
                        uint16_t uuid = data[17] + (data[18] << 8);
                        per_do_read_by_type(fd, start, end, uuid);
                    } else {
                        per_send_err(fd, ATT_OP_READ_BY_TYPE_REQ, start, ATT_ERROR_ATTRIBUTE_NOT_FOUND);
                    }
                } else {
                    per_send_err(fd, ATT_OP_READ_BY_TYPE_REQ, start, ATT_ERROR_INVALID_PDU);
                }
            } else {
                per_send_err(fd, ATT_OP_READ_BY_TYPE_REQ, 0, ATT_ERROR_INVALID_PDU);
            }
            break;

        case ATT_OP_WRITE_CMD :
        case ATT_OP_WRITE_REQ :
            if (len >= 3) {
                uint16_t handle = data[1] + (data[2] << 8);
                if (check_start_end(handle, s_numAttributes) == 0) {
                    per_do_write(fd, handle, data + 3, len - 3, cmd);
                } else {
                    if (cmd != ATT_OP_WRITE_CMD) {
                        per_send_err(fd, cmd, handle, ATT_ERROR_INVALID_HANDLE);
                    }
                }
            } else  {
                if (cmd != ATT_OP_WRITE_CMD) {
                    per_send_err(fd, cmd, 0, ATT_ERROR_INVALID_PDU);
                }
            }
            break;

        case ATT_OP_READ_REQ :
            DEBUG("read");
            /* TODO implement this in case someone does a read on the client config attribute */
            break;

        case ATT_OP_READ_BY_GROUP_TYPE_REQ :
            if (len > 5) {
                uint16_t start = data[1] + (data[2] << 8);
                uint16_t end = data[3] + (data[4] << 8);
                if (len == 7) {
                    uint16_t uuid = data[5] + (data[6] << 8);
                    DEBUG("read_by_group_type: start=%d,end=%d,uuid=%x", start, end, uuid);
                    if (uuid == GATT_PRIM_SVC_UUID) {
                        /* we only support one service */
                        if (start == 1 && end >= start) {
                            uint8_t send_buf[2 + 4 + 16];
                            send_buf[0] = ATT_OP_READ_BY_GROUP_TYPE_RESP;
                            send_buf[1] = 20;
                            send_buf[2] = 1 & 0xff;
                            send_buf[3] = 1 >> 8;
                            send_buf[4] = s_numAttributes & 0xff;
                            send_buf[5] = s_numAttributes >> 8;
                            memcpy(send_buf + 6, g_gattAferoHubServiceUuid, sizeof(g_gattAferoHubServiceUuid));
                            per_send(fd, send_buf, sizeof(send_buf));
                        } else {
                            per_send_err(fd, cmd, start, ATT_ERROR_ATTRIBUTE_NOT_FOUND);
                        }
                    } else {
                        /* not implemented */
                        ERROR("read by group for other UUIDs not implemented uuid=%d", uuid);
                    }
                } else if (len == 21) {
                    ERROR("read_by_group_type_long_not_implemented:start=%d,end=%d", start, end);
                } else {
                    per_send_err(fd, cmd, 0, ATT_ERROR_INVALID_PDU);
                }
            } else {
                per_send_err(fd, cmd, 0, ATT_ERROR_INVALID_PDU);
            }

            break;

        case ATT_OP_FIND_BY_TYPE_VALUE_REQ :
            if (len >= 7) {
                uint16_t start = data[1] + (data[2] << 8);
                uint16_t end = data[3] + (data[4] << 8);
                uint16_t type = data[5] + (data[6] << 8);
                uint8_t *value = data + 7;
                size_t value_len = len - 7;

                data2hex(buf, sizeof(buf), value, value_len);
                DEBUG("find_by_type_value start=%04x end=%04x type=%04x value=%s", start, end, type, buf);

                if (check_start_end(start, end) != 0) {
                    per_send_err(fd, ATT_OP_READ_BY_TYPE_REQ, start, ATT_ERROR_INVALID_HANDLE);
                    break;
                }
                if (type == GATT_PRIM_SVC_UUID && value_len == 16) {
                    if (memcmp(value, g_gattAferoHubServiceUuid, sizeof(g_gattAferoHubServiceUuid)) == 0) {
                        /* handle 1 is the "primary" service descriptor, the rest are the hub service */
                        uint8_t send_buf[1 + 4];
                        send_buf[0] = ATT_OP_FIND_BY_TYPE_VALUE_RESP;
                        send_buf[1] = 0x02;
                        send_buf[2] = 0;
                        send_buf[3] = (s_numAttributes + 1) & 0xff;
                        send_buf[4] = (s_numAttributes + 1) >> 8;
                        per_send(fd, send_buf, sizeof(send_buf));
                        break;
                    }
                }
                per_send_err(fd, cmd, start, ATT_ERROR_ATTRIBUTE_NOT_FOUND);
            }
            break;

        case ATT_OP_HANDLE_CNF :
            /* confirmed an indication */
            if (s_indicationUuid >= 0) {
                send_cmd("pin %04x %04x", s_indicationUuid, STATUS_OK);
                s_indicationUuid = 0;
            }
            break;

        case ATT_OP_EXCHANGE_MTU_REQUEST :
        {
            uint8_t buf[3];
            buf[0] = ATT_OP_EXCHANGE_MTU_RESPONSE;
            buf[1] = MAX_PACKET_SIZE & 0xff;
            buf[2] = MAX_PACKET_SIZE >> 8;
            per_send(fd, buf, sizeof(buf));
        }
        default:
            break;
    }
}
