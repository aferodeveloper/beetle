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
#ifndef __BEETLE_H__
#define __BEETLE_H__

#include "hci_beetle.h"

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
#define STATUS_BAD_PARAM         0x0d
#define STATUS_ALREADY_IN_MODE   0x0e
#define STATUS_WRONG_MODE        0x0f
#define STATUS_DATABASE_FULL     0x10
#define STATUS_UNKNOWN_CMD       0x11

#define COMMANDS \
    ENTRY(DEBUG,"deb","i",cmd_debug,either) \
    ENTRY(MODE,"mod","s",cmd_mode,either) \
    ENTRY(CONNECT,"con","s",cmd_connect,central) \
    ENTRY(CANCEL,"can","s",cmd_cancel_connect,central) \
    ENTRY(DISCONNECT,"dis","i",cmd_disconnect,central) \
    ENTRY(KATTRIBUTES,"kat","i",cmd_kattributes,central) \
    ENTRY(WRITE,"wri","iis",cmd_write,central) \
    ENTRY(READ,"rea","ii",cmd_read,central) \
    ENTRY(NOTIFY_ENABLE,"nen","iii",cmd_notify_enable,central) \
    ENTRY(SHH,"shh","",cmd_quiet,central) \
    ENTRY(PER_ADVERTISEMENT,"pad","iis",cmd_per_advertisement,peripheral) \
    ENTRY(PER_NOTIFY,"pin","is",cmd_per_indicate,peripheral) \
    ENTRY(PER_KATTRIBUTE,"pka","ii",cmd_per_kattribute,peripheral) \
    ENTRY(PER_DISCONNECT, "pdi", "", cmd_per_disconnect, peripheral)

#define ENTRY(ww,xx,yy,zz,aa) int zz(void *param1, void *param2, void *param3, void *context);

COMMANDS

#undef ENTRY

typedef int (*session_function_t)(int clientFd, bhci_t *bhci);

#define SESSION_SWITCH_SESSION      -1
#define SESSION_FAILED_NONFATAL     -2
#define SESSION_FAILED_FATAL        -3
#define SESSION_REBUILD_BLUETOOTH   -4

typedef enum {
    eitherSession = 0,
    centralSession,
    peripheralSession
} session_type_t;

int send_cmd(char *fmt, ...);
int dying(void);
int signaled(void);

session_type_t get_session_type(void);

/* size of Bluetooth address in ASCII */
#define BT_ADDR_SIZE 18

#endif // __BEETLE_H__
