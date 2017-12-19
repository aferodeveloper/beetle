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

#pragma once

#include <syslog.h>

enum {
    DEBUG_OFF = 0,
    DEBUG_ON = 1,
    DEBUG_TRACE = 2
};

extern int g_debugging;

#define _LOG(level, format, ...) do { \
  if (g_debugging >= level) syslog(LOG_DEBUG, format, ## __VA_ARGS__); \
} while (0)

#define ERROR(format, ...) syslog(LOG_ERR, format, ## __VA_ARGS__)
#define WARNING(format, ...)  syslog(LOG_WARNING, format, ## __VA_ARGS__)
#define INFO(format, ...)  syslog(LOG_INFO, format, ## __VA_ARGS__)
#define DEBUG(format, ...) _LOG(DEBUG_ON, format, ## __VA_ARGS__)
#define TRACE(format, ...) _LOG(DEBUG_TRACE, format, ## __VA_ARGS__)

void debug_level_increase(void);
void debug_level_decrease(void);
void log_failure(char *what);
