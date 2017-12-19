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

#ifndef __BABYGATT_COMMON_H__
#define __BABYGATT_COMMON_H__

#define ATT_OP_ERROR                    0x01
#define ATT_OP_EXCHANGE_MTU_REQUEST     0x02
#define ATT_OP_EXCHANGE_MTU_RESPONSE    0x03
#define ATT_OP_FIND_INFO_REQ            0x04
#define ATT_OP_FIND_INFO_RESP           0x05
#define ATT_OP_FIND_BY_TYPE_VALUE_REQ   0x06
#define ATT_OP_FIND_BY_TYPE_VALUE_RESP  0x07
#define ATT_OP_READ_BY_TYPE_REQ         0x08
#define ATT_OP_READ_BY_TYPE_RESP        0x09
#define ATT_OP_READ_REQ                 0x0A
#define ATT_OP_READ_RESP                0x0B
#define ATT_OP_READ_BY_GROUP_TYPE_REQ   0x10
#define ATT_OP_READ_BY_GROUP_TYPE_RESP  0x11
#define ATT_OP_WRITE_REQ                0x12
#define ATT_OP_WRITE_RESP               0x13
#define ATT_OP_WRITE_CMD                0x52
#define ATT_OP_HANDLE_NOTIFY            0x1B
#define ATT_OP_HANDLE_IND               0x1D
#define ATT_OP_HANDLE_CNF               0x1E

#define ATT_UUID16_FORMAT  1
#define ATT_UUID128_FORMAT 2

#define GATT_PRIM_SVC_UUID              0x2800
#define GATT_CHARAC_UUID                0x2803
#define GATT_CLIENT_CHARAC_CFG_UUID     0x2902

#define UUID_PREAMBLE_SIZE 12
#define UUID_SIZE 16

#define GATT_CHARACTERISTIC_BROADCAST          0x01
#define GATT_CHARACTERISTIC_READ               0x02
#define GATT_CHARACTERISTIC_WRITE_NO_RESPONSE  0x04
#define GATT_CHARACTERISTIC_WRITE              0x08
#define GATT_CHARACTERISTIC_NOTIFY             0x10
#define GATT_CHARACTERISTIC_INDICATE           0x20
#define GATT_CHARACTERISTIC_SIGNED_WRITES      0x40
#define GATT_CHARACTERISTIC_EXTENDED_PROPS     0x80

#define DEFAULT_BLE_MTU       23
#define MAX_PACKET_SIZE       DEFAULT_BLE_MTU

#define ATT_ERROR_INVALID_HANDLE            0x01
#define ATT_ERROR_READ_NOT_PERMITTED        0x02
#define ATT_ERROR_WRITE_NOT_PERMITTED       0x03
#define ATT_ERROR_INVALID_PDU               0x04
#define ATT_ERROR_ATTRIBUTE_NOT_FOUND       0x0A
#define ATT_ERROR_INVALID_ATTRIBUTE_LENGTH  0x0D

#define GATT_AFERO_UUID_PREAMBLE        0x6b, 0x69, 0x62, 0x61, 0x6e, 0x42, 0x4c, 0x45, 0x75, 0x75, 0x69, 0x64
#define GATT_DFU_UUID_PREAMBLE          0x23, 0xd1, 0xbc, 0xea, 0x5f, 0x78, 0x23, 0x15, 0xde, 0xef, 0x12, 0x12
#define GATT_AFERO_HUB_SERVICE_UUID     GATT_AFERO_UUID_PREAMBLE, 0xaf, 0xaf, 0x5a, 0x7a

extern uint8_t g_gattAferoUuidPreamble[UUID_PREAMBLE_SIZE];
extern uint8_t g_gattDfuUuidPreamble[UUID_PREAMBLE_SIZE];
extern uint8_t g_gattAferoHubServiceUuid[UUID_SIZE];

#endif // __BABYGATT_COMMON_H__
