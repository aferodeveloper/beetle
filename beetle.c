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

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <fcntl.h>
#include <stdarg.h>
#include <syslog.h>

#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>

#include "beetle.h"
#include "command.h"
#include "devicelist.h"
#include "connlist.h"
#include "utils.h"
#include "babygatt.h"

int g_debug = 1;            /* enable debug messages by default */

static int s_clientFd = -1; /* client socket                    */
static int s_hciFd    = -1; /* socket for sending HCI commands  */
static int s_rawHciFd = -1; /* socket for reading raw HCI       */
static int s_signal = 0;

#define SET_SCAN_TIMEOUT    5000
#define CONNECT_TIMEOUT     5000
#define NO_SOCKET_FD        0xffff
#define OPEN_ATTEMPT_DELAY  20
#define MAX_OPEN_ATTEMPTS   10

#define COMMAND_BUFFER_SIZE 2048

#define MAX_FDS_TO_RESERVE 8

static void reserve_fd(int fd)
{
    int fds[MAX_FDS_TO_RESERVE];
    int rfd;

    int i;
    /* open sockets until we get the specified fd */
    for (i = 0; i < MAX_FDS_TO_RESERVE; i++) {
        rfd = socket(PF_BLUETOOTH, SOCK_SEQPACKET | SOCK_NONBLOCK, BTPROTO_L2CAP);
        if (rfd == fd) {
            /* we have the specified fd; close all previous fds and exit */
            int j;
            for (j = 0; j < i; j++) {
                close(fds[j]);
            }
            if (g_debug >= 1) {
                syslog(LOG_DEBUG,"reserved fd %x", rfd);
            }
            return;
        }

        fds[i] = rfd;
    }

    /* we failed to reserve the fd; close all the ones we reserved */
    for (i = 0; i < MAX_FDS_TO_RESERVE; i++) {
        close(fds[i]);
    }

    syslog(LOG_ERR,"Failed to reserve fd %x", fd);
}

static void log_failure(char *what)
{
    int err = errno;

    syslog(LOG_ERR, "%s failed:err=\"%s\"", what, strerror(err));
    if (err == ENODEV) {
        syslog(LOG_EMERG, "bluetooth device disappeared!");
    }
}

#define SCAN_ENABLE  1
#define SCAN_DISABLE 0
static int s_scan_enabled = 0;

static int set_scan_enable (int hciFd, int enable)
{
    if (hciFd < 0) {
        errno = EBADF;
        return -1;
    }

    if (s_scan_enabled != enable) {
        s_scan_enabled = enable;
        if (hci_le_set_scan_enable(hciFd, (enable ? 0x01 : 0x00), 0, htobs(SET_SCAN_TIMEOUT)) < 0) {
            syslog(LOG_ERR,"set_scan_enable:enable=%d,error=%s", enable, strerror(errno));
            return -1;
        }
    }
    return 0;
}

#define CMD_BUF_SIZE 1024
int send_cmd(char *fmt, ...)
{
    char buf[CMD_BUF_SIZE];
    va_list va;
    int len;

    if (s_clientFd < 0) {
        errno = EBADF;
        return -1;
    }

    va_start(va, fmt);
    len = vsnprintf (buf, sizeof(buf), fmt, va);
    va_end(va);

    /* don't log advertisements */
    if (buf[0] != 'a' && g_debug >= 1) {
        syslog(LOG_DEBUG, "<%s", buf);
    }

    int res = write (s_clientFd, buf, len);
    if (res < 0) {
        return res;
    }
    return write (s_clientFd, "\n", 1);
}

static int readline(int s, char* dst, int len)
{
    int i;
    for (i = 0; i < len-1; i++) {
        char c;
        if (recv(s,&c,1,0) != 1) {
            log_failure("readline recv");
            return -1;
        }
        if (c == '\n') {
            dst[i] = '\0';
            return 0;
        }
        dst[i] = c;
    }
    syslog(LOG_ERR,"readline too long");
    return -1;
};

/* hci socket is used for scanning for advertisements */

static int hci_connect(int devid)
{
    if (devid < 0) {
        devid = 0;
    }
    int fd = hci_open_dev(devid);
    if (fd == -1) {
        syslog(LOG_ERR, "hci_open_dev failed:err=%s", strerror(errno));
        return -1;
    }

    /* time = n * 0.625 msec */
    int interval = 200;
    int window = interval;
    int res;

    s_scan_enabled = 0; /* assume that scan is disabled */

    /* set passive scanning with a five second timeout */
	if (hci_le_set_scan_parameters(fd, 0, htobs(interval), htobs(window), 0, 0, htobs(SET_SCAN_TIMEOUT)) < 0) {
        syslog(LOG_ERR, "hci_le_set_scan_parameters failed:err=%s", strerror(errno));
        close(fd);
        return -1;
    }

    /* enable scanning */
    res = set_scan_enable(fd, SCAN_ENABLE);

    if (res < 0) {
        log_failure("hci_connect_set_scan_enabled");
        close(fd);
        return -1;
    } else {
        return fd;
    }
}

static int disconnect(int hciFd, int handle)
{
    if (hci_disconnect(hciFd, htobs(handle), HCI_CONNECTION_TERMINATED, 10000) < 0) {
        log_failure("hci_disconnect");
        return -1;
    }
    return 0;
}

static int kill_connections(int hciFd)
{
    struct hci_conn_list_req *cl;
    struct hci_conn_info *ci;
    int i;

    cl = (struct hci_conn_list_req *)malloc(10 * sizeof(*ci) + sizeof(*cl));
    cl->dev_id = 0;
    cl->conn_num = 10;

    if (ioctl(hciFd, HCIGETCONNLIST, (void *) cl)) {
        free(cl);
        log_failure("HCIGETCONNLIST");
    }

    ci = cl->conn_info;
    for (i = 0; i < cl->conn_num; i++, ci++) {
        char addr[18];
        ba2str(&ci->bdaddr, addr);
        syslog(LOG_INFO,"Disconnecting %s",addr);
        disconnect(hciFd, ci->handle);
    }
    free(cl);
    return 0;
}

static int device_connect(const char *addr, int addr_type, const char *deviceId)
{
    if (s_hciFd < 0 || s_clientFd < 0) {
        errno = EBADF;
        return -1;
    }

    if (g_debug >= 1) {
        syslog(LOG_DEBUG,"device_connect: %d %s %d", s_hciFd, addr, addr_type);
    }

    bdaddr_t l2_bdaddr;
    uint16_t handle = -1;
    str2ba (addr, &l2_bdaddr);
    if (hci_le_create_conn(
        s_hciFd,            /* device              */
        htobs(0x00A0),      /* interval (100 ms)   */
        htobs(0x00A0),      /* window (continuous) */
        0,                  /* initiator filter    */
        addr_type,          /* peer address type   */
        l2_bdaddr,          /* peer address        */
        LE_PUBLIC_ADDRESS,  /* own address type    */
        htobs(0x0013),      /* min interval        */
        htobs(0x0013),      /* max interval        */
        htobs(0x0009),      /* latency             */
        htobs(0x0190),      /* supervision timeout */
        htobs(0x0000),      /* min ce length       */
        htobs(0x0000),      /* max ce length       */
        &handle,            /* return handle       */
        10000) < 0) {       /* timeout             */

        if (errno == ETIMEDOUT) { // If timed out, cancel connection

            uint8_t reply;
            struct hci_request hr;

            memset(&hr, 0, sizeof(hr));
            hr.ogf = OGF_LE_CTL;
            hr.ocf = OCF_LE_CREATE_CONN_CANCEL;

            hr.cparam = NULL;
            hr.clen = 0;
            hr.rparam = &reply;
            hr.rlen = sizeof(reply);

            if (hci_send_req(s_hciFd, &hr, 5000) < 0) {
                syslog(LOG_WARNING,"Conn Timeout: failed to cancel:%s",strerror(errno));
            } else {
                syslog(LOG_WARNING,"Conn Timeout: cancel status=0x%02x", reply);
            }

            send_cmd("con %s %04x %04x", addr, STATUS_TIMED_OUT, 0);
            return -1;
        } else {
            send_cmd("con %s %04x %04x", addr, STATUS_IO_ERROR, 0);
            log_failure("connection create");
            return -1;
        }
    }

    /* convert to host endian */
    handle = btohs(handle);

    if (g_debug >= 1) {
        syslog(LOG_DEBUG,"Connection handle for %s is %d", addr, handle);
    }
    return handle;
}

static int l2cap_connect (const char* addr, int cid, int addr_type)
{
    if (g_debug >= 1) {
        syslog(LOG_DEBUG,"l2cap_connect: %s %d",addr,addr_type);
    }

    int l2capSocket = socket(PF_BLUETOOTH, SOCK_SEQPACKET | SOCK_NONBLOCK, BTPROTO_L2CAP);
    if (l2capSocket < 0) {
        log_failure("l2cap connect:socket");
        return -1;
    }

    /* set the socket type to l2cap */
    struct sockaddr_l2 sockAddr;
    memset (&sockAddr, 0, sizeof(sockAddr));
    sockAddr.l2_family = AF_BLUETOOTH;
    sockAddr.l2_cid = htobs(cid);

    if (bind(l2capSocket, (struct sockaddr*)&sockAddr, sizeof(sockAddr)) < 0) {
        log_failure("bind");
        return -1;
    }

    /* connect to the device */
    str2ba(addr, &sockAddr.l2_bdaddr);
    sockAddr.l2_bdaddr_type = addr_type;
    if (connect (l2capSocket, (struct sockaddr *)&sockAddr, sizeof(sockAddr)) < 0) {
        if (errno != EINPROGRESS) {
            log_failure("connect");
            return -1;
        }
    }
    return l2capSocket;
}

/* open a raw hci socket to view LE metadata events */
static int open_raw_hci(int dev)
{
    /* open the socket */
    int s = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
    if (s < 0) {
        log_failure("hci raw socket");
        return -1;
    }

    /* set the data direction */
    int opt = 1;
    if (setsockopt(s, SOL_HCI, HCI_DATA_DIR, &opt, sizeof(opt)) < 0) {
        log_failure("HCI_DATA_DIR");
    }

    /* set up the packet filter */
    struct hci_filter flt;
    hci_filter_clear(&flt);
    hci_filter_all_ptypes(&flt);
    hci_filter_all_events(&flt);
    if (setsockopt(s, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
        log_failure("HCI_FILTER");
    }

    /* bind the hci socket to the specified device */
    struct sockaddr_hci addr;
    memset (&addr, 0, sizeof(addr));
    addr.hci_family = AF_BLUETOOTH;
    addr.hci_dev = dev;

    if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        log_failure("hci raw socket bind");
        return -1;
    }

    return s;
}

/* handle connect command */
int cmd_connect(void *param1, void *param2, void *param3)
{
    // find the device address
    device_info_t *di = dl_find_by_addr((char *)param1);
    if (di == NULL) {
        syslog(LOG_ERR,"unknown device %s", (char *)param1);
        send_cmd("con %s %04x %04x", (char *)param1, STATUS_UNKNOWN_DEVICE, 0);
        return -1;
    }

    // check if the device is already connected
    conn_info_t *ci = cl_find_by_addr(di->addr);
    if (ci != NULL) {
        syslog(LOG_ERR,"device %s is already connected", (char *)param1);
        send_cmd("con %s %04x %04x", (char *)param1, STATUS_ALREADY_CONNECTED, 0);
        return -1;
    }

    // get a free connection handle
    ci = cl_get_unused();
    if (ci == NULL) {
        syslog(LOG_ERR,"connection list is full");
        send_cmd("con %s %04x %04x", (char *)param1, STATUS_CONN_LIST_FULL, 0);
        return -1;
    }

    ci->d_info = di;
    ci->l2cap_fd = -1;

    // Get connection ID
    ci->conn_id  = 4;

    // Turn off scanning for connect
    set_scan_enable(s_hciFd, SCAN_DISABLE);

    // Connect the device
    syslog(LOG_INFO, "connecting %s %04x %04x", ci->d_info->addr, ci->d_info->addr_type, ci->conn_id);
    ci->hci_handle = device_connect(ci->d_info->addr, ci->d_info->addr_type, (char *)param1);
    if (ci->hci_handle == -1) {
        cl_free(ci);
        return -1;
    }

    // Create L2CAP connection
    ci->l2cap_fd = l2cap_connect(ci->d_info->addr, ci->conn_id, ci->d_info->addr_type);

    if (g_debug >= 1) {
        syslog(LOG_DEBUG,"connecting %s %d", di->addr, ci->l2cap_fd);
    }

    if (ci->l2cap_fd == -1) {
        send_cmd("con %s %04x %04x", (char *)param1, STATUS_L2CAP_CONN_FAILED, 0);
        cl_free(ci);
        return -1;
    } else {
        ci->state = CONN_STATE_CONNECTING;
    }

    return 0;
}

/* handle rssi command */
int cmd_rssi(void *param1, void *param2, void *param3)
{
    int l2cap_fd = *(int *)param1;
    conn_info_t *ci = cl_find_by_l2cap_fd(&l2cap_fd);

    if (ci == NULL) {
        send_cmd("rsi %04x %04x %d", l2cap_fd, STATUS_UNKNOWN_CONN, 0);
        log_failure("read rssi");
    }

    if (ci->state != CONN_STATE_CONNECTED) {
        send_cmd("rsi %04x %04x %d", l2cap_fd, STATUS_NOT_CONNECTED, 0);
        log_failure("read rssi");
    }

    int8_t rssi;

    if (hci_read_rssi(s_hciFd, htobs(ci->hci_handle), &rssi, 1000) < 0) {
        if (errno == ETIMEDOUT) {
            send_cmd("rsi %04x %04x %d", l2cap_fd, STATUS_TIMED_OUT, 0);
        } else {
            send_cmd("rsi %04x %04x %d", l2cap_fd, STATUS_IO_ERROR, 0);
        }
        log_failure("read rssi");
    }

    send_cmd("rsi %04x %04x %d", l2cap_fd, STATUS_OK, rssi);
    return 0;
}

/* handle disconnect comand */
int cmd_disconnect(void *param1, void *param2, void *param3)
{
    int l2cap_fd = *(int *)param1;
    conn_info_t *ci = cl_find_by_l2cap_fd(&l2cap_fd);

    if (ci == NULL) {
        syslog(LOG_ERR,"l2cap_fd %d not found", l2cap_fd);
        send_cmd("dis %04x %04x", l2cap_fd, STATUS_UNKNOWN_CONN);
        return -1;
    }

    syslog(LOG_INFO,"disconnecting %s", ci->d_info->addr);

    ci->state = CONN_STATE_DISCONNECTING;
#if 1
    close(ci->l2cap_fd);      /* Do not hci disconnect because of Bluez bugs on big endian systems    */
    reserve_fd(ci->l2cap_fd); /* reserve the file descriptor so Linux doesn't give it to someone else */
#else
    if (disconnect(ci->hci_handle) < 0) {
        log_failure("disconnect");
        if (ci->l2cap_fd != -1) {
            close(ci->l2cap_fd);
        }
        ci->state = CONN_STATE_DISCONNECTED;
        send_cmd("dis %s %04x", ci->addr, ci->l2cap_fd);
    }
#endif
    return 0;
}

/* handle debug command */
int cmd_debug(void *param1, void *param2, void *param3)
{
    g_debug = *(int *)param1;
    send_cmd("deb %04x", STATUS_OK);
    return 0;
}

/* handle data command */
int cmd_data(void *param1, void *param2, void *param3)
{
    uint8_t request[COMMAND_BUFFER_SIZE / 2];          // L2CAP data
    int l2cap_fd = *(int *)param1;
    int i = hex2data ((char *)param2, request, COMMAND_BUFFER_SIZE);
    if (write (l2cap_fd, request, i) != i) {
        log_failure("l2cap send");
    }
    return 0;
}

static int addr2str(uint8_t *addr, char *str)
{
    return sprintf (str,"%02x:%02x:%02x:%02x:%02x:%02x",addr[5],addr[4],addr[3],addr[2],addr[1],addr[0]);
}

static void parse_advertisement(uint8_t *data)
{
    char addr[BT_ADDR_SIZE];
    int len = data[13];
    int i;
    uint8_t afero_device = 0;
    uint8_t addr_type = data[6];            /* random vs. public */
    int8_t rxpower;
    char manufacturerData[64];

    /* set the bluetooth address */
    addr2str(&data[7], addr);

    /* start to parse the advertisement */
    data += 14;
    for (i = 0; i < len;) {
        int field_len = data[i]-1;
        uint8_t *d = data + i + 2;          /* TODO check bounds!!! */
        if (data[i+1] == 0xFF) {            /* manufacturer data */
            if (field_len >= 11 && (d[0] == 0xD2) && d[1] == 0x02) {
                afero_device = 1;
                data2hex(manufacturerData, sizeof(manufacturerData), d, field_len);
            }
        }
        i += field_len + 2;
    }
    rxpower = (int8_t)data[i];

    if (afero_device) {
        dl_add_device(addr, addr_type);
        send_cmd("adv %s %s %d", addr, manufacturerData, rxpower);
    }
}

static void handle_raw_packet(uint8_t *data, int len, int numConnecting)
{
    char hexData[2048];

    /* Do some packet interpretation */
    if (data[0] == HCI_EVENT_PKT) {                         /* Event */

        if (data[1] == EVT_LE_META_EVENT) {                 /* LE Meta Event */

            if (data[3] == EVT_LE_CONN_COMPLETE) {          /* LE Connection Complete */

                char addr[BT_ADDR_SIZE];
                int handle = data[5] + (data[6] << 8);
                addr2str(&data[9], addr);
                syslog(LOG_INFO,"LE_CONNECT: addr = %s handle = %d", addr, handle);

                conn_info_t *ci = cl_find_by_addr(addr);
                if (ci != NULL) {
                    ci->state = CONN_STATE_CONNECTED;
                    ci->hci_handle = handle;
                    send_cmd("con %s %04x %04x", ci->d_info->addr, STATUS_OK, ci->l2cap_fd);
                }

                if (numConnecting == 0) {
                    set_scan_enable(s_hciFd, SCAN_ENABLE);
                }

                if (g_debug >= 1) {
                    syslog(LOG_DEBUG,"enable scan on connect finished");
                }
            } else if (data[3] == EVT_LE_ADVERTISING_REPORT) {
                parse_advertisement(data);
            } else if (g_debug >= 2) {
                syslog(LOG_DEBUG,"hci %s",data2hex(hexData, sizeof(hexData), data, len));
            }
        } else if (data[1] == EVT_DISCONN_COMPLETE) {       /* Disconnection Complete */

            int hci_handle = data[4] + (data[5] << 8);
            int status = data[3];
            int reason = data[6];
            syslog(LOG_INFO,"DISCONNECT hci_handle=%d status=0x%02x reason=0x%02x", hci_handle, status, reason);
            conn_info_t *ci = cl_find_by_hci_handle(&hci_handle);
            if (ci != NULL) {
                close(ci->l2cap_fd);

                send_cmd("dis %04x %04x %04x", ci->l2cap_fd, STATUS_OK, reason);
                cl_free(ci);
            }
        }
    }
}

struct select_set {
    int    maxFd;
    fd_set fds;
};

static void handle_l2cap_data(conn_info_t *ci, void *arg)
{
    struct select_set *ss = (struct select_set *)arg;
    fd_set *fdsp = (fd_set *)&ss->fds;

    if (FD_ISSET(ci->l2cap_fd, fdsp))
    {
        // Data
        uint8_t response[1024];
        char hexData[2048];
        int len = read(ci->l2cap_fd, response, sizeof(response));
        if (len > 0) {
            if (g_debug >= 2) {
                syslog(LOG_DEBUG, "l2r %04x %s", ci->l2cap_fd, data2hex(hexData, 2048, response, len));
            }
            on_data(ci, response, len);
        } else {
            syslog(LOG_ERR,"l2 read error %s disconnecting %d", strerror(errno), ci->l2cap_fd);
            ci->state = CONN_STATE_DISCONNECTING;
            close(ci->l2cap_fd);
        }
    }
}

static void handle_l2cap_select(conn_info_t *ci, void *arg)
{
    struct select_set *ss = (struct select_set *)arg;

    FD_SET(ci->l2cap_fd, &ss->fds);
    if (ci->l2cap_fd > ss->maxFd) {
        ss->maxFd = ci->l2cap_fd;
    }
}

static void handle_l2cap_close(conn_info_t *ci, void *arg)
{
    close(ci->l2cap_fd);
    cl_free(ci);
}

static void session(void)
{
    s_hciFd = -1;
    s_rawHciFd = -1;

    /* try to open hci sockets */
    int i;
    for (i = 0; i < MAX_OPEN_ATTEMPTS; i++) {
        int dev;

        dev = hci_get_route(NULL);
        s_rawHciFd = open_raw_hci(dev);
        if (s_rawHciFd >= 0) {

            s_hciFd = hci_connect(dev);
            if (s_hciFd >= 0) {
                break;
            } else {
                close(s_rawHciFd);
                s_rawHciFd = -1;
            }
        }
        sleep(OPEN_ATTEMPT_DELAY);
    }

    /* return if we failed to open sockets too many times */
    if (i >= MAX_OPEN_ATTEMPTS) {
        return;
    }

    syslog(LOG_INFO,"raw on %d, hci on %d", s_rawHciFd, s_hciFd);

    /* close any existing HCI connections */
    kill_connections(s_hciFd);

    /* clear the connection list */
    cl_init();

    while (1)
    {
        /* check if a signal occurred when we weren't looking */
        if (s_signal) {
            break;
        }

        /* expire devices that haven't been seen for a while */
        dl_expire_devices();

        /* count connections in progress */
        int numConnecting = cl_get_connecting();
        if (numConnecting == 0) {
            set_scan_enable(s_hciFd, SCAN_ENABLE);
        }

        /* Create select structure with fd list and max */
        struct select_set ss;

        /* add the communication socket and raw HCI socket */
        ss.maxFd = (s_clientFd > s_rawHciFd ? s_clientFd : s_rawHciFd);

        FD_ZERO(&ss.fds);
        FD_SET(s_clientFd, &ss.fds);
        FD_SET(s_rawHciFd, &ss.fds);

        /* add the open L2CAP sockets */
        cl_foreach_connected(handle_l2cap_select, &ss);

        /* set up the select */
        struct timeval tv = { 1, 0 };
        int result = select(ss.maxFd + 1, &ss.fds, NULL, NULL, &tv);

        if (result < 0) {              /* error on select */
            log_failure("select");
            break;
        }

        if (result == 0) {             /* time out */
            if (numConnecting == 0) {
                set_scan_enable(s_hciFd, SCAN_ENABLE);
            }
            continue;
        }

        if (FD_ISSET(s_rawHciFd, &ss.fds)) {   /* data on raw HCI socket */
            uint8_t data[1024];
            int len = read(s_rawHciFd, data, sizeof(data));
            if (len <= 0) {
                log_failure("HCI raw read");
                break;
            }

            handle_raw_packet(data, len, numConnecting);
        }

        if (FD_ISSET(s_clientFd, &ss.fds)) {  /* Command in from socket */
            char buf[COMMAND_BUFFER_SIZE];

            if (readline(s_clientFd, buf, sizeof(buf))) {
                log_failure("cmd read");
                break;
            }
            if (g_debug >= 1) {
                syslog(LOG_DEBUG,">%s",buf);
            }

            handle_command(buf);
        }

        /* handle L2CAP data received */
        cl_foreach_connected(handle_l2cap_data, &ss);
    }

    syslog(LOG_WARNING,"closing session");

    // stop scanning
	set_scan_enable(s_hciFd, SCAN_DISABLE);

    // close all connections
    cl_foreach_connected(handle_l2cap_close, NULL);

    close(s_rawHciFd);
    s_rawHciFd = -1;

    close(s_hciFd);
    s_hciFd = -1;
}

int set_up_listener(void)
{
    struct sockaddr_in servaddr;

    /* create the socket */
    int listenFd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenFd < 0) {
        log_failure("echo server socket");
        return -1;
    }

    int optval = 1;
    if (setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int)) < 0) {
        log_failure("echo server setsockopt");
        close(listenFd);
        return -1;
    }

    memset(&servaddr,0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(6969);

    if (bind(listenFd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        log_failure("bind");
        close(listenFd);
        return -1;
    }

    if (listen(listenFd, 1024) < 0) {
        log_failure("listen");
        close(listenFd);
        return -1;
    }
    syslog(LOG_INFO,"listening...");
    return listenFd;
}

static int accept_connection(int listenFd)
{
    struct sockaddr_in clientaddr;
    socklen_t len = sizeof(clientaddr);

    int clientFd = accept(listenFd, (struct sockaddr *)&clientaddr, &len);
    if (clientFd < 0) {
        log_failure("accept");
        return -1;
    }

    syslog(LOG_INFO, "Connection from %s", inet_ntoa(clientaddr.sin_addr));

    return clientFd;
}

static void on_signal(int signal)
{
    if (s_hciFd >= 0) {
        s_signal = signal;
    } else {
        exit(128 + signal);
    }
}

static void set_up_signals(void)
{
    // Set signal handlers
    sigset_t sigset;
    sigemptyset(&sigset);
    struct sigaction siginfo = {
        .sa_handler = on_signal,
        .sa_mask = sigset,
        .sa_flags = 0,
    };

    sigaction(SIGINT, &siginfo, NULL);
    sigaction(SIGTERM, &siginfo, NULL);
}

#define PID_FILE_PATH "/var/run/beetle.pid"

int main(int argc, const char* argv[])
{
    int daemonize = 0;

    if (argc > 1) {
        if (argv[1][0] == '-' && argv[1][1] == 'd') {
            daemonize = 1;
        }
    }

    if (daemonize) {
        pid_t pid = fork();
        if (pid < 0) {
            syslog(LOG_ERR,"fork failed errno=%d", errno);
            exit(1);
        } else if (pid != 0) {
            exit(0);
        }
    }

    set_up_signals();

    openlog("beetle", LOG_PID | LOG_NDELAY, LOG_USER);

    int listenFd = set_up_listener();
    if (listenFd < 0) {
        goto exit;
    }

    while (1) {
        s_clientFd = accept_connection(listenFd);

        if (s_clientFd >= 0) {
            session();
            syslog(LOG_INFO,"Disconnecting");
            close(s_clientFd);
        }

        /* we can safely exit without BlueZ issues here */
        if (s_signal) {
            close(listenFd);
            closelog();
            exit(128 + s_signal);
        }
    }

    close(listenFd);

exit:
    closelog();
    return 0;
}
