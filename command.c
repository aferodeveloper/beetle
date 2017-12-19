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

#include <string.h>
#include <stdio.h>
#include "command.h"
#include "beetle.h"
#include "log.h"
#include "utils.h"

#define COMMAND_BUFFER_SIZE 2048

typedef int (*command_handler_t) (void *param1, void *param2, void *param3, void *context);

typedef struct {
    char *name;
    char *param_types;
    command_handler_t func;
    session_type_t sessionType;
} command_t;

#define ENTRY(ww,xx,yy,zz,aa) ww,
typedef enum {
    COMMANDS
    NUM_COMMANDS
} command_enum_t;

#undef ENTRY
#define ENTRY(ww,xx,yy,zz,aa) { xx,yy,zz,aa ## Session },
static command_t s_cmds[] = {
    COMMANDS
};

#define MAX_PARAMS 3

static int readline(int s, char *buffer, int len) {
    int i;
    for (i = 0; i < len-1; i++) {
        char c;
        if (recv(s,&c,1,0) != 1) {
            log_failure("readline recv");
            return -1;
        }
        if (c == '\n') {
            buffer[i] = '\0';
            return 0;
        }
        buffer[i] = c;
    }
    ERROR("readline too long");
    return -1;
}

static int handle_command(char *line, void *context) {
    char *tok, *save;
    int cmd, j, num_params;
    void *params[MAX_PARAMS];
    int integers[MAX_PARAMS];

    memset(params, 0, sizeof(params));

    /* match the command */
    tok = strtok_r(line, " \r", &save);

    if (tok == NULL) {
        return 0;
    }

    for (cmd = 0; cmd < NUM_COMMANDS; cmd++) {
        if (!strcmp(s_cmds[cmd].name, tok)) {
            break;
        }
    }

    if (cmd >= NUM_COMMANDS) {
        send_cmd("%s %04x", tok, STATUS_UNKNOWN_CMD);
        return 0;
    }

    if (s_cmds[cmd].sessionType != eitherSession && s_cmds[cmd].sessionType != get_session_type()) {
        send_cmd("%s %04x", tok, STATUS_WRONG_MODE);
        return 0;
    }

    char *name = tok;

    /* get and convert the parameters */
    memset(params, 0, sizeof(params));
    num_params = strlen(s_cmds[cmd].param_types);
    for (j = 0; j < num_params; j++) {
        tok = strtok_r(NULL, " \r", &save);
        if (tok == NULL) {
            ERROR("expected %d params but found %d", num_params, j);
            send_cmd("%s %04x", name, STATUS_BAD_PARAM);
            return 0;
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
    return (*s_cmds[cmd].func)(params[0], params[1], params[2], context);
}

int read_and_execute_client_command(int fd, void *context) {
    char buf[COMMAND_BUFFER_SIZE];

    if (readline(fd, buf, sizeof(buf))) {
        log_failure("cmd read");
        return SESSION_FAILED_FATAL;
    }
    DEBUG(">%s", buf);

    return handle_command(buf, context);
}
