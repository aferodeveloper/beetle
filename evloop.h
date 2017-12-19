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

typedef struct evloop evloop_t;

typedef enum {
    EL_ERROR = -1,
    EL_STOPPED = 0
} evloop_result_t;

typedef enum {
    EL_CONTINUE = 0,
    EL_STOP = 1
} evloop_handler_result_t;

typedef evloop_handler_result_t (*evloop_handler_t)(evloop_t *ev, int fd, void *arg);

typedef struct {
    void *arg;
    evloop_handler_t handler;
} evloop_fd_t;

typedef struct evloop {
    int running;
    int size;
    evloop_fd_t *read_fds;
    evloop_fd_t *write_fds;
    evloop_fd_t signals[32];
    evloop_fd_t periodic;
    int result_code;
} evloop_t;

void evloop_init(evloop_t *ev);
void evloop_free(evloop_t *ev);
void evloop_stop(evloop_t *ev, int result_code);
int evloop_on_read(evloop_t *ev, int fd, evloop_handler_t handler, void *arg);
int evloop_on_write(evloop_t *ev, int fd, evloop_handler_t handler, void *arg);
int evloop_on_signal(evloop_t *ev, int signal, evloop_handler_t handler, void *arg);
int evloop_periodic(evloop_t *ev, evloop_handler_t handler, void *arg);
evloop_result_t evloop_run(evloop_t *ev);

#define evloop_cancel_read(ev, fd) evloop_on_read(ev, fd, NULL, NULL)
#define evloop_cancel_write(ev, fd) evloop_on_write(ev, fd, NULL, NULL)
