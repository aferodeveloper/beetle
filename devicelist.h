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
#ifndef __DEVICELIST_H__
#define __DEVICELIST_H__

#include <stdint.h>
#include <bluetooth/bluetooth.h>
#include <time.h>
#include "beetle.h"

typedef struct {
    uint16_t attribute_id;          /* 0 if end of list */
    uint16_t write_handle;
    uint16_t read_handle;
    uint16_t read_config_handle;
    uint8_t isIndication;
    uint8_t isNoResponse;
} kattribute_t;

typedef struct {
    char addr[BT_ADDR_SIZE];
    char addr_type;
    char pad;
    time_t lastSeen;
    int8_t rssi;
    kattribute_t *attributes;
} device_info_t;

device_info_t *dl_find_by_addr(char *addr);

device_info_t *dl_add_device(char *addr, char addr_type);

kattribute_t *dl_find_attr(device_info_t *di, int attr);

void dl_expire_devices(void);

void dl_debug(void);

// TODO add a clean up

#endif // __DEVICELIST_H__
