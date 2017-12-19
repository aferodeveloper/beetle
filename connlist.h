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
#ifndef __CONNLIST_H__
#define __CONNLIST_H__

#include <stddef.h>
#include <stdint.h>
#include "devicelist.h"

#define CONN_STATE_DISCONNECTED      0
#define CONN_STATE_CONNECTING        1  /* setting up hci parameters */
#define CONN_STATE_CONNECTING_L2CAP  2  /* asking for new l2cap socket */
#define CONN_STATE_CONNECTED         3  /* received read params & ready */
#define CONN_STATE_DISCONNECTING     4

#define CONN_FLAGS_PENDING_OP    (1 << 0)

#define MAX_ATTRIBUTES 16

typedef struct {
    int state;
    int conn_id;
    int l2cap_fd;
    uint16_t hci_handle;
    int flags;
    int attr_id; // attribute ID for outstanding read or write (can't be interleaved)
    int pend_cmd; // outstanding command;
    device_info_t *d_info;
    kattribute_t attr_list[MAX_ATTRIBUTES];
    int num_attr;
    time_t connect_started;
} conn_info_t;

void cl_init();

int cl_size(void);

conn_info_t *cl_find_by_offset_size(void *search, int offset,int size);

#define cl_find_by_l2cap_fd(lll) cl_find_by_offset_size(lll,offsetof(conn_info_t,l2cap_fd),sizeof(int))
#define cl_find_by_hci_handle(hhh) cl_find_by_offset_size(hhh,offsetof(conn_info_t,hci_handle),sizeof(uint16_t))

conn_info_t *cl_find_by_addr(char *addr);

conn_info_t *cl_get_unused(void);

void cl_foreach_state(int state, void (*callback)(conn_info_t *ci, void *arg), void *arg);

void cl_free(conn_info_t *ci);

int cl_get_connecting(void);

#endif // __CONNLIST_H__
