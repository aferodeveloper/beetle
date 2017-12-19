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

#include <errno.h>
#include <string.h>
#include "log.h"

/* for now, always log at trace */
int g_debugging = DEBUG_TRACE;

void debug_level_increase(void) {
    if (g_debugging < DEBUG_TRACE) g_debugging++;
}

void debug_level_decrease(void) {
    if (g_debugging > 0) g_debugging--;
}

void log_failure(char *what) {
    int err = errno;

    syslog(LOG_ERR, "%s failed: errno=%d, %s", what, err, strerror(err));
    if (err == ENODEV) {
        syslog(LOG_EMERG, "bluetooth device disappeared!");
    }
}
