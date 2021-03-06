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

#ifndef __COMMAND_H__
#define __COMMAND_H__

#include "beetle.h"

/* line is terminated with a newline '\n' */
/* returns -1 if the session should end   */
/* returns 0 otherwise                    */
int read_and_execute_client_command(int fd, void *context);

#endif //__COMMAND_H__
