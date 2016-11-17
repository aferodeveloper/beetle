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

#include <ctype.h>
#include <stdint.h>
#include <syslog.h>
#include <stdio.h>
#include "utils.h"

extern int g_debug;

static const char _hex[] = "0123456789abcdef";

static void hex(char* dst, int n)
{
    dst[0] = _hex[n >> 4];
    dst[1] = _hex[n & 0xF];
}

char *data2hex(char *dest, int dest_size, const uint8_t* data, int len)
{
    int i;
    if (len < 0 || (len * 2 + 1) > dest_size) {
        syslog(LOG_ERR,"bad len in data2Hex:%d",len);
    }
    for (i = 0; i < len; i++) {
        hex(dest + i*2, *data++);
    }
    dest[len*2] = '\0';
    return dest;
}

int hex2data(const char* s, uint8_t* data, int bufSize)
{
    int i = 0;
    while (*s && i < bufSize) {
        int c, d = tolower(*s++) - '0';
        d -= (d > 9 ? 'a' - '0' - 0x0a : 0);

        if (*s == '\0') {
            return i; // Truncate last nybble
        }

        c = tolower(*s++) - '0';
        c -= (c > 9 ? 'a' - '0' - 0x0a : 0);

        data[i++] = (d << 4) + c;
    }
    return i;
}

char *data2hexLE(char* dst, uint8_t* data, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        sprintf (dst + i * 2, "%02x", data[len - i - 1]);
    }
    return dst;
}

