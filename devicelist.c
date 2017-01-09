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
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include "devicelist.h"

extern int g_debug;

#define MAX_DEVICES 128
static int s_numDevices=0;
static device_info_t s_devices[MAX_DEVICES];

#define SECONDS_BETWEEN_CULLINGS 60             /* cull every minute */
static time_t s_lastCulledTime = 0;

#define SECONDS_TO_EXPIRE_DEVICE (25 * 60 * 60) /* expire a device after 25 hours */

static time_t get_mono_time(void)
{
    struct timespec tspec;
    if (clock_gettime(CLOCK_MONOTONIC, &tspec) < 0) {
        syslog(LOG_ERR, "can't get monotonic time:err=\"%s\"", strerror(errno));
        return 0;
    } else {
        return tspec.tv_sec;
    }
}

/* if the return value >= 0, the address is found and the return value is the index
 * if the return value is -1, the index where the address should be inserted is
 * returned in the insertIndex parameter
 */
static int find_by_addr(char *addr, int *insertIndex)
{
    int lo = -1, hi = s_numDevices;

    while (hi - lo != 1) {
        int g = lo + (hi - lo) / 2;
        int comp = strcmp(addr, s_devices[g].addr);
        if (comp < 0) {
            hi = g;
        } else if (comp > 0) {
            lo = g;
        } else {
            return g;
        }
    }
    if (insertIndex != NULL) {
        *insertIndex = hi;
    }
    return -1;
}

device_info_t *dl_find_by_addr(char *addr)
{
    if (s_numDevices == 0) {
        return NULL;
    }

    int i = find_by_addr(addr, NULL);
    if (i < 0) {
        return NULL;
    }
    return &s_devices[i];
}

int dl_add_device(char *addr, char addr_type)
{
    int iPos;
    if (s_numDevices > 0) {
        int i = find_by_addr(addr, &iPos);
        if (i >= 0) {
            s_devices[i].lastSeen = get_mono_time();
            return -1;
        }
    } else {
        iPos = 0;
    }

    if (s_numDevices < MAX_DEVICES) {
        int i;

        /* insert device into the list */
        for (i = s_numDevices - 1; i >= iPos; i--) {
            memcpy(&s_devices[i + 1], &s_devices[i], sizeof(device_info_t));
        }

        device_info_t *di = &s_devices[iPos];

        /* clear out the device info */
        memset(di, 0, sizeof(device_info_t));

        /* set the address and type */
        strncpy(di->addr, addr, BT_ADDR_SIZE - 1);
        di->addr[BT_ADDR_SIZE-1] = '\0';
        di->addr_type = addr_type;
        di->lastSeen = get_mono_time();

        s_numDevices++;

        if (g_debug >= 1) {
            syslog(LOG_DEBUG,"Added addr=%s,type=%d,numDevices=%d", addr, addr_type, s_numDevices);
        }
        return 0;
    }

    syslog(LOG_ERR,"Can't add device %s: device list is full", addr);
    return -1;
}

kattribute_t *dl_find_attr(device_info_t *di, int attr)
{
    kattribute_t *ka;

    if (di == NULL) {
        return NULL;
    }

    ka = di->attributes;
    if (ka == NULL) {
        return NULL;
    }

    while (ka->attribute_id != 0) {
        if (ka->attribute_id == attr) {
            return ka;
        }
        ka++;
    }

    return NULL;
}

static void cull_devices(void)
{
    int i, store = 0, numExpired = 0;
    time_t t = get_mono_time();

    if (t < SECONDS_TO_EXPIRE_DEVICE) {
        return;
    }

    time_t expireTime = t - SECONDS_TO_EXPIRE_DEVICE;

    for (i = 0; i < s_numDevices; i++) {
        if (s_devices[i].lastSeen < expireTime) {
            numExpired++;
            if (g_debug >= 1) {
                syslog(LOG_INFO, "expiring addr=%s,numDevices=%d", s_devices[i].addr, s_numDevices - numExpired);
            }
        } else {
            if (i != store) {
                memcpy(&s_devices[store], &s_devices[i], sizeof(device_info_t));
            }
            store++;
        }
    }
    s_numDevices -= numExpired;
}

void dl_expire_devices(void)
{
    time_t t = get_mono_time();
    if (t - s_lastCulledTime > SECONDS_BETWEEN_CULLINGS) {
        cull_devices();
        s_lastCulledTime = t;
    }
}

