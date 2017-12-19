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

#include "connlist.h"
#include "log.h"

#define MAX_BLE_CONNECTIONS 8

static conn_info_t s_conns[MAX_BLE_CONNECTIONS];
static int s_num_conns = 0;

int cl_size(void)
{
    return s_num_conns;
}

conn_info_t *cl_find_by_offset_size(void *search, int offset, int size)
{
    int i;
    for (i = 0; i < s_num_conns; i++) {
        if (!memcmp(search, ((uint8_t *)&s_conns[i]) + offset, size)) {
            return &s_conns[i];
        }
    }

    return NULL;
}

conn_info_t *cl_find_by_addr(char *addr)
{
    int i;
    for (i = 0; i < s_num_conns; i++) {
        if (s_conns[i].d_info && !memcmp(addr, s_conns[i].d_info->addr, BT_ADDR_SIZE)) {
            return &s_conns[i];
        }
    }

    return NULL;
}

conn_info_t *cl_get_unused(void)
{
    if (s_num_conns < MAX_BLE_CONNECTIONS) {
        // clear the connection data
        memset(&s_conns[s_num_conns], 0, sizeof(conn_info_t));
        return &s_conns[s_num_conns++];
    }
    return NULL;
}

void cl_free(conn_info_t *ci)
{
    int i,j;

    for (i = 0; i < s_num_conns; i++) {
        if (ci == &s_conns[i]) {
            break;
        }
    }

    if (i >= s_num_conns) {
        ERROR("can't free connection info; not allocated");
        return;
    }

    // move the rest of the connections down
    for (j = i + 1; j < s_num_conns; j++) {
        memcpy(&s_conns[j - 1], &s_conns[j], sizeof(conn_info_t));
    }

    s_num_conns--;
}

int cl_get_connecting()
{
    int i, r=0;

    for (i = 0; i < s_num_conns; i++) {
        if (s_conns[i].state == CONN_STATE_CONNECTING) {
            r++;
        }
    }

    return r;
}

void cl_foreach_state(int state, void (*callback)(conn_info_t *ci, void *arg), void *arg) {
    int i;

    for (i = 0; i < s_num_conns; i++) {
        if (s_conns[i].state == state) {
            device_info_t *d_info = s_conns[i].d_info;
            callback(&s_conns[i], arg);
            /* callback may have deleted the connection */
            if (d_info != s_conns[i].d_info) i--;
        }
    }
}

void cl_init(void) {
    memset(s_conns, 0, sizeof(s_conns));
    s_num_conns = 0;
}
