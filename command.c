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

#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include "command.h"
#include "beetle.h"

extern int g_debug;

typedef int (*command_handler_t) (void *param1, void *param2, void *param3);

typedef struct {
    char *name;
    char *param_types;
    command_handler_t func;
} command_t;

#define ENTRY(ww,xx,yy,zz) ww,
typedef enum {
    COMMANDS
    NUM_COMMANDS
} command_enum_t;

#undef ENTRY
#define ENTRY(ww,xx,yy,zz) { xx,yy,zz },
static command_t s_cmds[] = {
    COMMANDS
};

#define MAX_PARAMS 3

int handle_command(char *line)
{
    char *tok, *save;
    int cmd, j, num_params;
    void *params[MAX_PARAMS];
    int integers[MAX_PARAMS];

    memset(params, 0, sizeof(params));

    /* match the command */
    tok = strtok_r(line, " \r", &save);

    if (tok == NULL) {
        return -1;
    }

    for (cmd = 0; cmd < NUM_COMMANDS; cmd++) {
        if (!strcmp(s_cmds[cmd].name, tok)) {
            break;
        }
    }

    if (cmd >= NUM_COMMANDS) {
        syslog(LOG_ERR,"command %s unknown", tok);
        return -1;
    }

    /* get and convert the parameters */
    num_params = strlen(s_cmds[cmd].param_types);
    for (j = 0; j < num_params; j++) {

        tok = strtok_r(NULL, " \r", &save);
        if (tok == NULL) {
            syslog(LOG_ERR,"expected %d params but found %d", num_params, j);
            return -1;
        }

        switch (s_cmds[cmd].param_types[j]) {
            case 's' :
                params[j] = (void *)tok;
                break;
            case 'i' :
                sscanf(tok, "%04x", &integers[j]);
                params[j] = &integers[j];
                break;
            default :
                break;
        }
    }

    /* execute the command */
    return (*s_cmds[cmd].func)(params[0], params[1], params[2]);
}

