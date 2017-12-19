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
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>

#include "beetle.h"
#include "evloop.h"
#include "log.h"
#include "utils.h"

#define DEFAULT_FD_SIZE 4

void evloop_init(evloop_t *ev) {
    memset(ev, 0, sizeof(evloop_t));
    ev->size = DEFAULT_FD_SIZE;
    ev->read_fds = calloc(ev->size, sizeof(evloop_fd_t));
    ev->write_fds = calloc(ev->size, sizeof(evloop_fd_t));
    if (ev->read_fds == NULL || ev->write_fds == NULL) {
        /* don't try to recover if we can't even allocate the smallest chunk of memory on init. */
        log_failure("event_loop_init");
        exit(1);
    }
}

void evloop_free(evloop_t *ev) {
    free(ev->read_fds);
    free(ev->write_fds);
    memset(ev, 0, sizeof(evloop_t));
}

static int evloop_grow(evloop_t *ev, int new_size) {
    int i;

    evloop_fd_t *new_read_fds = realloc(ev->read_fds, sizeof(evloop_fd_t) * new_size);
    if (new_read_fds == NULL) return -1;
    ev->read_fds = new_read_fds;

    evloop_fd_t *new_write_fds = realloc(ev->write_fds, sizeof(evloop_fd_t) * new_size);
    if (new_write_fds == NULL) return -1;
    ev->write_fds = new_write_fds;

    for (i = ev->size; i < new_size; i++) {
        memset(&ev->read_fds[i], 0, sizeof(evloop_fd_t));
        memset(&ev->write_fds[i], 0, sizeof(evloop_fd_t));
    }
    ev->size = new_size;
    return 0;
}

void evloop_stop(evloop_t *ev, int result_code) {
    ev->running = 0;
    ev->result_code = result_code;
}

int evloop_on_read(evloop_t *ev, int fd, evloop_handler_t handler, void *arg) {
    if (fd >= ev->size && evloop_grow(ev, fd + 8) != 0) return -1;
    ev->read_fds[fd].handler = handler;
    ev->read_fds[fd].arg = arg;
    return 0;
}

int evloop_on_write(evloop_t *ev, int fd, evloop_handler_t handler, void *arg) {
    if (fd >= ev->size && evloop_grow(ev, fd + 8) != 0) return -1;
    ev->write_fds[fd].handler = handler;
    ev->write_fds[fd].arg = arg;
    return 0;
}

int evloop_on_signal(evloop_t *ev, int signal, evloop_handler_t handler, void *arg) {
    ev->signals[signal].handler = handler;
    ev->signals[signal].arg = arg;
    return 0;
}

int evloop_periodic(evloop_t *ev, evloop_handler_t handler, void *arg) {
    ev->periodic.handler = handler;
    ev->periodic.arg = arg;
    return 0;
}

evloop_result_t evloop_run(evloop_t *ev) {
    fd_set read_fds;
    fd_set write_fds;
    int i;

    ev->running = 1;

    while (ev->running) {
        if (dying()) break;

        int signal = signaled();
        if (signal != 0 && ev->signals[signal].handler != NULL) {
            ev->signals[signal].handler(ev, signal, ev->signals[signal].arg);
            continue;
        }

        if (ev->periodic.handler) {
            if (ev->periodic.handler(ev, 0, ev->periodic.arg) != EL_CONTINUE) break;
        }

        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        for (i = 0; i < ev->size; i++) {
            if (ev->read_fds[i].handler != NULL) FD_SET(i, &read_fds);
            if (ev->write_fds[i].handler != NULL) FD_SET(i, &write_fds);
        }

        struct timeval tv = { 1, 0 };
        int count = select(ev->size, &read_fds, &write_fds, NULL, &tv);

        if (count < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            log_failure("select");
            return EL_ERROR;
        }
        if (count == 0) continue;

        for (i = 0; i < ev->size; i++) {
            if (FD_ISSET(i, &read_fds) && ev->read_fds[i].handler) {
                evloop_handler_t fn = ev->read_fds[i].handler;
                void *arg = ev->read_fds[i].arg;
                ev->read_fds[i].handler = NULL;
                if (fn(ev, i, ev->read_fds[i].arg) == EL_CONTINUE) {
                    ev->read_fds[i].handler = fn;
                    ev->read_fds[i].arg = arg;
                }
            }

            if (FD_ISSET(i, &write_fds) && ev->write_fds[i].handler) {
                evloop_handler_t fn = ev->write_fds[i].handler;
                void *arg = ev->write_fds[i].arg;
                ev->write_fds[i].handler = NULL;
                if (fn(ev, i, ev->write_fds[i].arg) == EL_CONTINUE) {
                    ev->write_fds[i].handler = fn;
                    ev->write_fds[i].arg = arg;
                }
            }
        }
    }

    return EL_STOPPED;
}
