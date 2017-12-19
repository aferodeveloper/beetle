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
#ifndef __BABYGATT_CENTRAL_H__
#define __BABYGATT_CENTRAL_H__

#include "connlist.h"

void on_central_data(conn_info_t *ci, uint8_t *data, int len);
void gatt_fail_any_pending(conn_info_t *ci, int error_code);

#endif // __BABYGATT_CENTRAL_H__
