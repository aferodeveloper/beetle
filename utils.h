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
#ifndef __UTILS_H__
#define __UTILS_H__

#include <time.h>

char *data2hex(char *dest, int dest_size, const uint8_t *data, int len);
int hex2data(const char *s, uint8_t *data, int len);
char *data2hexLE(char *dst, uint8_t *data, int len);
int addr2str(void *addr, char *str);
time_t get_mono_time(void);

#endif // __UTILS_H__
