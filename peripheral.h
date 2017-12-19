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

#ifndef __PERIPHERAL_SESSION_H__
#define __PERIPHERAL_SESSION_H__

#include "evloop.h"
#include "hci_beetle.h"

struct peripheral_context {
    /* l2cap listener */
    int listen_fd;

    /* any existing hub connection */
    int connection_fd;

    /* address of connected hub */
    char addr[BT_ADDR_SIZE];

    bhci_t *bhci;
    evloop_t *ev;
};

int peripheral_session(int client_fd, bhci_t *bhci);

#endif // __PERIPHERAL_SESSION_H__
