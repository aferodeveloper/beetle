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
#ifndef __BEETLE_H__
#define __BEETLE_H__

#define STATUS_OK                0x00
#define STATUS_UNKNOWN_CONN      0x01
#define STATUS_UNKNOWN_ATTR      0x02
#define STATUS_PENDING           0x03
#define STATUS_NOT_PERMITTED     0x04
#define STATUS_IO_ERROR          0x05
#define STATUS_UNKNOWN_DEVICE    0x06 
#define STATUS_ALREADY_CONNECTED 0x07 
#define STATUS_CONN_LIST_FULL    0x08 
#define STATUS_TIMED_OUT         0x09 
#define STATUS_L2CAP_CONN_FAILED 0x0a 
#define STATUS_NOT_CONNECTED     0x0b 
#define STATUS_BLUETOOTH_ERROR   0x0c

#define COMMANDS \
    ENTRY(CMD_CONNECT,"con","s",cmd_connect) \
    ENTRY(CMD_DISCONNECT,"dis","i",cmd_disconnect) \
    ENTRY(CMD_RSSI,"rsi","i",cmd_rssi) \
    ENTRY(CMD_DEBUG,"deb","i",cmd_debug) \
    ENTRY(CMD_DATA,"dat","is",cmd_data) \
    ENTRY(CMD_KATTRIBUTES,"kat","i",cmd_kattributes) \
    ENTRY(CMD_WRITE,"wri","iis",cmd_write) \
    ENTRY(CMD_READ,"rea","ii",cmd_read) \
    ENTRY(CMD_NOTIFY_ENABLE,"nen","iii",cmd_notify_enable)

#define ENTRY(ww,xx,yy,zz) int zz(void *param1, void *param2, void *param3);

COMMANDS

#undef ENTRY

int send_cmd(char *fmt, ...);

#endif // __BEETLE_H__
