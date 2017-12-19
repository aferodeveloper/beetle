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

#include <stdint.h>
#include "babygatt_common.h"

uint8_t g_gattAferoUuidPreamble[UUID_PREAMBLE_SIZE] = { GATT_AFERO_UUID_PREAMBLE };
uint8_t g_gattDfuUuidPreamble[UUID_PREAMBLE_SIZE]   = { GATT_DFU_UUID_PREAMBLE };
uint8_t g_gattAferoHubServiceUuid[UUID_SIZE]        = { GATT_AFERO_HUB_SERVICE_UUID };
