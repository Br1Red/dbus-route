#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <errno.h>
#include <stddef.h>
#include <getopt.h>
#include <time.h>

#define MAX_ROUTES 100
#define MAX_CLIENTS 64
#define BUF_SIZE 65536
#define MAX_PENDING 8192
#define MAX_FDS 16

typedef struct {
    char *destination;
    char *socket_path;
    uid_t uid;
    int uid_set;
} RouteConfig;

RouteConfig routes[MAX_ROUTES];
int route_count = 0;
char *listen_socket_path = NULL;
char *default_socket_path = NULL;
uid_t default_uid = 0;
int default_uid_set = 0;
int debug_enabled = 0;
uid_t auth_uid = 0;
int auth_uid_set = 0;

static void print_log_timestamp(FILE *stream) {
    struct timespec now;
    struct tm local_time;
    char time_string[9];

    clock_gettime(CLOCK_REALTIME, &now);
    localtime_r(&now.tv_sec, &local_time);
    strftime(time_string, sizeof(time_string), "%H:%M:%S", &local_time);
    fprintf(stream, "[%s.%03ld] ", time_string, now.tv_nsec / 1000000L);
}

#define LOG(stream, ...) do { print_log_timestamp(stream); fprintf(stream, __VA_ARGS__); } while(0)
#define DBG(...) do { if (debug_enabled) LOG(stdout, __VA_ARGS__); } while(0)
#define ERR(...) LOG(stderr, __VA_ARGS__)

// ---------- Struttura per trasportare FD ancillary ----------

typedef struct {
    int fds[MAX_FDS];
    int num_fds;
} AncillaryFds;

// ---------- Utilità I/O con supporto ancillary data ----------

static int send_all(int fd, const char *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0) return -1;
        sent += n;
    }
    return sent;
}

// Invio con fd ancillary
static int send_all_with_fds(int fd, const char *buf, int len, AncillaryFds *afds) {
    if (!afds || afds->num_fds == 0) {
        return send_all(fd, buf, len);
    }
    
    struct iovec iov = { .iov_base = (void *)buf, .iov_len = len };
    
    char cmsgbuf[CMSG_SPACE(sizeof(int) * MAX_FDS)];
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsgbuf,
        .msg_controllen = CMSG_SPACE(sizeof(int) * afds->num_fds),
    };
    
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int) * afds->num_fds);
    memcpy(CMSG_DATA(cmsg), afds->fds, sizeof(int) * afds->num_fds);
    
    int sent = 0;
    while (sent < len) {
        iov.iov_base = (void *)(buf + sent);
        iov.iov_len = len - sent;
        
        if (sent > 0) {
            msg.msg_control = NULL;
            msg.msg_controllen = 0;
        }
        
        ssize_t n = sendmsg(fd, &msg, MSG_NOSIGNAL);
        if (n <= 0) return -1;
        sent += n;
    }
    return sent;
}

// Lettura con supporto per fd ancillary (usato solo per il primo chunk)
static ssize_t recv_with_fds(int fd, void *buf, size_t len, AncillaryFds *afds) {
    struct iovec iov = { .iov_base = buf, .iov_len = len };
    
    char cmsgbuf[CMSG_SPACE(sizeof(int) * MAX_FDS)];
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsgbuf,
        .msg_controllen = sizeof(cmsgbuf),
    };
    
    ssize_t n = recvmsg(fd, &msg, 0);
    if (n <= 0) return n;
    
    if (afds) {
        afds->num_fds = 0;
        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
                int nfds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                if (nfds > MAX_FDS) nfds = MAX_FDS;
                memcpy(afds->fds, CMSG_DATA(cmsg), sizeof(int) * nfds);
                afds->num_fds = nfds;
            }
        }
    }
    
    return n;
}

static int recv_line(int fd, char *buf, int maxlen) {
    int i = 0;
    while (i < maxlen - 1) {
        int n = read(fd, buf + i, 1);
        if (n <= 0) return -1;
        if (buf[i] == '\n') { i++; break; }
        i++;
    }
    buf[i] = '\0';
    return i;
}

static int authenticate_to_bus(int fd, uid_t uid, int uid_set) {
    char nul = '\0';
    if (send(fd, &nul, 1, MSG_NOSIGNAL) != 1) return -1;

    char uid_str[32];
    uid_t effective_uid = uid_set ? uid : getuid();
    snprintf(uid_str, sizeof(uid_str), "%d", effective_uid);
    
    char hex_uid[64];
    int hlen = 0;
    for (int i = 0; uid_str[i]; i++) {
        hlen += sprintf(hex_uid + hlen, "%02x", (unsigned char)uid_str[i]);
    }
    
    char auth_cmd[128];
    snprintf(auth_cmd, sizeof(auth_cmd), "AUTH EXTERNAL %s\r\n", hex_uid);
    if (send_all(fd, auth_cmd, strlen(auth_cmd)) < 0) return -1;
    
    char resp[256];
    if (recv_line(fd, resp, sizeof(resp)) < 0) return -1;
    if (strncmp(resp, "OK ", 3) != 0) {
        ERR("[-] Auth fallita: %s\n", resp);
        return -1;
    }
    
    if (send_all(fd, "NEGOTIATE_UNIX_FD\r\n", 19) < 0) return -1;
    if (recv_line(fd, resp, sizeof(resp)) < 0) return -1;
    if (strncmp(resp, "AGREE_UNIX_FD", 13) != 0) {
        DBG("[!] Bus non supporta UNIX_FD: %s\n", resp);
    }
    
    if (send_all(fd, "BEGIN\r\n", 7) < 0) return -1;
    return 0;
}

static int authenticate_client(int fd) {
    char buf[256];
    
    char nul;
    if (read(fd, &nul, 1) != 1 || nul != '\0') return -1;
    
    if (recv_line(fd, buf, sizeof(buf)) < 0) return -1;
    DBG("[*] Client auth: %s", buf);
    
    if (strncmp(buf, "AUTH EXTERNAL", 13) == 0) {
        if (buf[13] == '\r' || buf[13] == '\n' || buf[13] == '\0') {
            const char *data = "DATA\r\n";
            DBG("[*] Client auth reply: %s", data);
            if (send_all(fd, data, strlen(data)) < 0) return -1;
            if (recv_line(fd, buf, sizeof(buf)) < 0) return -1;
            DBG("[*] Client auth: %s", buf);
            if (strncmp(buf, "DATA", 4) != 0 ||
                (buf[4] != ' ' && buf[4] != '\r' && buf[4] != '\n' && buf[4] != '\0')) return -1;
        }
        const char *ok = "OK 1234567890abcdef1234567890abcdef\r\n";
        DBG("[*] Client auth reply: %s", ok);
        if (send_all(fd, ok, strlen(ok)) < 0) return -1;
    } else if (strncmp(buf, "AUTH", 4) == 0) {
        const char *rejected = "REJECTED EXTERNAL\r\n";
        DBG("[*] Client auth reply: %s", rejected);
        send_all(fd, rejected, strlen(rejected));
        if (recv_line(fd, buf, sizeof(buf)) < 0) return -1;
        DBG("[*] Client auth: %s", buf);
        if (strncmp(buf, "AUTH EXTERNAL", 13) != 0) return -1;
        if (buf[13] == '\r' || buf[13] == '\n' || buf[13] == '\0') {
            const char *data = "DATA\r\n";
            DBG("[*] Client auth reply: %s", data);
            if (send_all(fd, data, strlen(data)) < 0) return -1;
            if (recv_line(fd, buf, sizeof(buf)) < 0) return -1;
            DBG("[*] Client auth: %s", buf);
            if (strncmp(buf, "DATA", 4) != 0 ||
                (buf[4] != ' ' && buf[4] != '\r' && buf[4] != '\n' && buf[4] != '\0')) return -1;
        }
        const char *ok = "OK 1234567890abcdef1234567890abcdef\r\n";
        DBG("[*] Client auth reply: %s", ok);
        if (send_all(fd, ok, strlen(ok)) < 0) return -1;
    } else {
        return -1;
    }
    
    while (1) {
        if (recv_line(fd, buf, sizeof(buf)) < 0) return -1;
        DBG("[*] Client auth: %s", buf);
        if (strncmp(buf, "BEGIN", 5) == 0) break;
        if (strncmp(buf, "NEGOTIATE_UNIX_FD", 17) == 0) {
            const char *agree = "AGREE_UNIX_FD\r\n";
            DBG("[*] Client auth reply: %s", agree);
            send_all(fd, agree, strlen(agree));
        }
    }
    
    return 0;
}

// ---------- Protocollo wire DBus ----------

typedef struct {
    uint8_t endian;
    uint8_t type;
    uint8_t flags;
    uint8_t version;
    uint32_t body_length;
    uint32_t serial;
    uint32_t header_fields_length;
} __attribute__((packed)) DBusRawHeader;

#define DBUS_HEADER_FIELD_PATH 1
#define DBUS_HEADER_FIELD_INTERFACE 2
#define DBUS_HEADER_FIELD_MEMBER 3
#define DBUS_HEADER_FIELD_ERROR_NAME 4
#define DBUS_HEADER_FIELD_REPLY_SERIAL 5
#define DBUS_HEADER_FIELD_DESTINATION 6
#define DBUS_HEADER_FIELD_SENDER 7
#define DBUS_HEADER_FIELD_SIGNATURE 8
#define DBUS_HEADER_FIELD_UNIX_FDS 9

#define DBUS_TYPE_METHOD_CALL 1
#define DBUS_TYPE_METHOD_RETURN 2
#define DBUS_TYPE_ERROR 3
#define DBUS_TYPE_SIGNAL 4

static inline uint32_t align8(uint32_t v) { return (v + 7) & ~7; }
static inline uint32_t align4(uint32_t v) { return (v + 3) & ~3; }

// Legge un messaggio DBus completo, catturando eventuali fd ancillary
static int read_dbus_message(int fd, uint8_t *buf, int bufsize, AncillaryFds *afds) {
    int hdr_size = 16;
    int total_read = 0;
    
    if (afds) afds->num_fds = 0;
    
    ssize_t n = recv_with_fds(fd, buf, bufsize, afds);
    if (n <= 0) return -1;
    total_read = n;
    
    if (total_read < hdr_size) {
        while (total_read < hdr_size) {
            n = read(fd, buf + total_read, hdr_size - total_read);
            if (n <= 0) return -1;
            total_read += n;
        }
    }
    
    DBusRawHeader *hdr = (DBusRawHeader *)buf;
    if (hdr->endian != 'l' && hdr->endian != 'B') {
        ERR("[-] Endian non valido: 0x%02x\n", hdr->endian);
        return -1;
    }
    
    uint32_t body_len = hdr->body_length;
    uint32_t fields_len = hdr->header_fields_length;
    uint32_t total_len = align8(12 + 4 + fields_len) + body_len;
    
    if ((int)total_len > bufsize) {
        ERR("[-] Messaggio troppo grande: %u\n", total_len);
        return -1;
    }
    
    while (total_read < (int)total_len) {
        n = read(fd, buf + total_read, total_len - total_read);
        if (n <= 0) return -1;
        total_read += n;
    }
    return total_len;
}

// Struttura per estrarre campi dal messaggio
typedef struct {
    const char *destination;
    uint32_t destination_len;
    const char *sender;
    uint32_t sender_len;
    const char *interface;
    const char *member;
    const char *path;
    uint32_t reply_serial;
    int has_reply_serial;
    int has_sender;
    uint32_t unix_fds;
    int has_unix_fds;
} MsgFields;

typedef struct {
    uint8_t code;
    char sig;
    union {
        struct { const char *str; uint32_t len; } s;
        uint32_t u;
    };
} HeaderField;

static int iterate_header_fields(const uint8_t *buf, int msglen,
    void (*callback)(const uint8_t *buf, int field_offset, HeaderField *f, void *ctx),
    void *ctx)
{
    uint32_t fields_len = *(uint32_t *)(buf + 12);
    const uint8_t *base = buf;
    const uint8_t *p = buf + 16;
    const uint8_t *end = p + fields_len;
    int count = 0;
    
    (void)msglen;
    
    while (p < end) {
        uintptr_t off = p - base;
        if (off % 8 != 0) p = base + align8(off);
        if (p >= end) break;
        
        int field_offset = p - base;
        uint8_t code = *p++;
        if (p >= end) break;
        uint8_t sig_len = *p++;
        if (p >= end || sig_len < 1) break;
        char sig = *p++;
        p++; // NUL
        
        HeaderField f;
        f.code = code;
        f.sig = sig;
        
        if (sig == 's' || sig == 'o') {
            uintptr_t off2 = p - base;
            if (off2 % 4 != 0) p = base + align4(off2);
            if (p + 4 > end + 4) break;
            uint32_t str_len = *(uint32_t *)p;
            p += 4;
            f.s.str = (const char *)p;
            f.s.len = str_len;
            p += str_len + 1;
            if (callback) callback(buf, field_offset, &f, ctx);
        } else if (sig == 'u') {
            uintptr_t off2 = p - base;
            if (off2 % 4 != 0) p = base + align4(off2);
            f.u = *(uint32_t *)p;
            p += 4;
            if (callback) callback(buf, field_offset, &f, ctx);
        } else if (sig == 'g') {
            uint8_t gl = *p++;
            f.s.str = (const char *)p;
            f.s.len = gl;
            p += gl + 1;
            if (callback) callback(buf, field_offset, &f, ctx);
        } else {
            break;
        }
        count++;
    }
    return count;
}

static void extract_fields_cb(const uint8_t *buf, int field_offset, HeaderField *f, void *ctx) {
    MsgFields *mf = (MsgFields *)ctx;
    (void)buf; (void)field_offset;
    switch (f->code) {
        case DBUS_HEADER_FIELD_DESTINATION:
            mf->destination = f->s.str;
            mf->destination_len = f->s.len;
            break;
        case DBUS_HEADER_FIELD_SENDER:
            mf->sender = f->s.str;
            mf->sender_len = f->s.len;
            mf->has_sender = 1;
            break;
        case DBUS_HEADER_FIELD_INTERFACE:
            mf->interface = f->s.str;
            break;
        case DBUS_HEADER_FIELD_MEMBER:
            mf->member = f->s.str;
            break;
        case DBUS_HEADER_FIELD_PATH:
            mf->path = f->s.str;
            break;
        case DBUS_HEADER_FIELD_REPLY_SERIAL:
            mf->reply_serial = f->u;
            mf->has_reply_serial = 1;
            break;
        case DBUS_HEADER_FIELD_UNIX_FDS:
            mf->unix_fds = f->u;
            mf->has_unix_fds = 1;
            break;
    }
}

static void extract_msg_fields(const uint8_t *buf, int msglen, MsgFields *mf) {
    memset(mf, 0, sizeof(*mf));
    iterate_header_fields(buf, msglen, extract_fields_cb, mf);
}

static void modify_reply_serial_inplace(uint8_t *buf, int msglen, uint32_t new_val) {
    uint32_t fields_len = *(uint32_t *)(buf + 12);
    uint8_t *p = buf + 16;
    uint8_t *end = p + fields_len;
    
    (void)msglen;
    
    while (p < end) {
        uintptr_t off = p - buf;
        if (off % 8 != 0) p = buf + align8(off);
        if (p >= end) break;
        uint8_t code = *p++;
        p++;
        char sig = *p++;
        p++;
        if (sig == 'u') {
            uintptr_t off2 = p - buf;
            if (off2 % 4 != 0) p = buf + align4(off2);
            if (code == DBUS_HEADER_FIELD_REPLY_SERIAL)
                *(uint32_t *)p = new_val;
            p += 4;
        } else if (sig == 's' || sig == 'o') {
            uintptr_t off2 = p - buf;
            if (off2 % 4 != 0) p = buf + align4(off2);
            uint32_t sl = *(uint32_t *)p; p += 4 + sl + 1;
        } else if (sig == 'g') {
            uint8_t gl = *p++; p += gl + 1;
        } else break;
    }
}

static void set_serial(uint8_t *buf, uint32_t serial) {
    *(uint32_t *)(buf + 8) = serial;
}

static uint32_t get_serial(const uint8_t *buf) {
    return *(uint32_t *)(buf + 8);
}

static int rewrite_header_field(uint8_t *buf, int msglen, int bufsize,
                                uint8_t field_code, const char *new_val) {
    uint32_t fields_len = *(uint32_t *)(buf + 12);
    uint32_t body_len = *(uint32_t *)(buf + 4);
    uint32_t old_body_start = align8(16 + fields_len);
    uint8_t *tmp;
    uint8_t *p;
    uint8_t *end;
    int out = 16;
    int found = 0;

    if (old_body_start + body_len > (uint32_t)msglen) return -1;

    tmp = calloc(1, bufsize);
    if (!tmp) return -1;
    memcpy(tmp, buf, 16);
    p = buf + 16;
    end = p + fields_len;

    while (p < end) {
        uint8_t *field_start;
        uint8_t code;
        char sig;

        p = buf + align8(p - buf);
        if (p + 4 > end) goto invalid;
        field_start = p;
        code = *p++;
        if (*p++ != 1) goto invalid;
        sig = *p++;
        if (*p++ != '\0') goto invalid;

        if (sig == 's' || sig == 'o') {
            uint32_t str_len;
            p = buf + align4(p - buf);
            if (p + 4 > end) goto invalid;
            str_len = *(uint32_t *)p;
            p += 4;
            if (p + str_len + 1 > end || p[str_len] != '\0') goto invalid;
            p += str_len + 1;
        } else if (sig == 'u') {
            p = buf + align4(p - buf);
            if (p + 4 > end) goto invalid;
            p += 4;
        } else if (sig == 'g') {
            uint8_t sig_len;
            if (p + 1 > end) goto invalid;
            sig_len = *p++;
            if (p + sig_len + 1 > end || p[sig_len] != '\0') goto invalid;
            p += sig_len + 1;
        } else {
            goto invalid;
        }

        if (code == field_code) {
            found = 1;
            if (!new_val) continue;
            if (sig != 's' && sig != 'o') goto invalid;

            out = align8(out);
            size_t new_len = strlen(new_val);
            int value_pos = align4(out + 4);
            if (new_len > UINT32_MAX || value_pos + 4 + new_len + 1 > (size_t)bufsize)
                goto invalid;
            tmp[out++] = code;
            tmp[out++] = 1;
            tmp[out++] = sig;
            tmp[out++] = '\0';
            while (out < value_pos) tmp[out++] = 0;
            *(uint32_t *)(tmp + out) = (uint32_t)new_len;
            out += 4;
            memcpy(tmp + out, new_val, new_len + 1);
            out += new_len + 1;
            continue;
        }

        out = align8(out);
        if (out + (p - field_start) > bufsize) goto invalid;
        memcpy(tmp + out, field_start, p - field_start);
        out += p - field_start;
    }

    if (!found) {
        free(tmp);
        return msglen;
    }

    *(uint32_t *)(tmp + 12) = out - 16;
    int new_body_start = align8(out);
    if (new_body_start + body_len > (uint32_t)bufsize) goto invalid;
    memset(tmp + out, 0, new_body_start - out);
    memcpy(tmp + new_body_start, buf + old_body_start, body_len);
    memcpy(buf, tmp, new_body_start + body_len);
    free(tmp);
    return new_body_start + body_len;

invalid:
    free(tmp);
    return -1;
}

static int replace_header_string_field(uint8_t *buf, int msglen, int bufsize,
                                        uint8_t field_code, const char *new_val) {
    return rewrite_header_field(buf, msglen, bufsize, field_code, new_val);
}

static int remove_header_field(uint8_t *buf, int msglen, int bufsize, uint8_t field_code) {
    return rewrite_header_field(buf, msglen, bufsize, field_code, NULL);
}

static int connect_unix(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    
    if (path[0] == '@') {
        addr.sun_path[0] = '\0';
        strncpy(addr.sun_path + 1, path + 1, sizeof(addr.sun_path) - 2);
        int len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(path + 1);
        if (connect(fd, (struct sockaddr *)&addr, len) < 0) { close(fd); return -1; }
    } else {
        strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    }
    return fd;
}

static char* send_hello(int fd, uint32_t *serial) {
    uint8_t buffer[512];
    int pos = 0;
    
    buffer[pos++] = 'l';
    buffer[pos++] = 0x01;
    buffer[pos++] = 0x00;
    buffer[pos++] = 0x01;
    int body_len_off = pos; pos += 4;
    *serial = 1;
    buffer[pos++] = 0x01; buffer[pos++] = 0x00; buffer[pos++] = 0x00; buffer[pos++] = 0x00;
    int fields_len_off = pos; pos += 4;
    int fields_start = pos;
    
    while (pos % 8 != 0) buffer[pos++] = 0;
    buffer[pos++] = 0x01;
    buffer[pos++] = 0x01; buffer[pos++] = 'o'; buffer[pos++] = 0x00;
    const char *path = "/org/freedesktop/DBus";
    int plen = strlen(path);
    while (pos % 4 != 0) buffer[pos++] = 0;
    *(uint32_t *)(buffer + pos) = plen; pos += 4;
    memcpy(buffer + pos, path, plen + 1); pos += plen + 1;
    
    while (pos % 8 != 0) buffer[pos++] = 0;
    buffer[pos++] = 0x02;
    buffer[pos++] = 0x01; buffer[pos++] = 's'; buffer[pos++] = 0x00;
    const char *iface = "org.freedesktop.DBus";
    int ilen = strlen(iface);
    while (pos % 4 != 0) buffer[pos++] = 0;
    *(uint32_t *)(buffer + pos) = ilen; pos += 4;
    memcpy(buffer + pos, iface, ilen + 1); pos += ilen + 1;
    
    while (pos % 8 != 0) buffer[pos++] = 0;
    buffer[pos++] = 0x03;
    buffer[pos++] = 0x01; buffer[pos++] = 's'; buffer[pos++] = 0x00;
    const char *member = "Hello";
    int mlen = strlen(member);
    while (pos % 4 != 0) buffer[pos++] = 0;
    *(uint32_t *)(buffer + pos) = mlen; pos += 4;
    memcpy(buffer + pos, member, mlen + 1); pos += mlen + 1;
    
    while (pos % 8 != 0) buffer[pos++] = 0;
    buffer[pos++] = 0x06;
    buffer[pos++] = 0x01; buffer[pos++] = 's'; buffer[pos++] = 0x00;
    const char *dest = "org.freedesktop.DBus";
    int dlen = strlen(dest);
    while (pos % 4 != 0) buffer[pos++] = 0;
    *(uint32_t *)(buffer + pos) = dlen; pos += 4;
    memcpy(buffer + pos, dest, dlen + 1); pos += dlen + 1;
    
    int fields_len = pos - fields_start;
    *(uint32_t *)(buffer + fields_len_off) = fields_len;
    *(uint32_t *)(buffer + body_len_off) = 0;
    while (pos % 8 != 0) buffer[pos++] = 0;
    
    if (send_all(fd, (char *)buffer, pos) < 0) return NULL;
    
    uint8_t resp[512];
    AncillaryFds afds = {0};
    int rlen = read_dbus_message(fd, resp, sizeof(resp), &afds);
    if (rlen < 0) return NULL;
    
    for (int i = 0; i < afds.num_fds; i++) close(afds.fds[i]);
    
    DBusRawHeader *hdr = (DBusRawHeader *)resp;
    if (hdr->type != DBUS_TYPE_METHOD_RETURN) return NULL;
    
    uint32_t hfields_len = *(uint32_t *)(resp + 12);
    int body_off = align8(16 + hfields_len);
    uint32_t name_len = *(uint32_t *)(resp + body_off);
    char *name = malloc(name_len + 1);
    memcpy(name, resp + body_off + 4, name_len);
    name[name_len] = '\0';
    return name;
}

static int select_bus_index(const char *destination) {
    if (destination == NULL) return route_count;
    for (int i = 0; i < route_count; i++) {
        if (strncmp(destination, routes[i].destination, strlen(routes[i].destination)) == 0) {
            return i;
        }
    }
    return route_count;
}

static int build_dbus_header_field_string(uint8_t *buf, int pos, uint8_t code, char sig_char, const char *val) {
    while (pos % 8 != 0) buf[pos++] = 0;
    buf[pos++] = code;
    buf[pos++] = 0x01; buf[pos++] = sig_char; buf[pos++] = 0x00;
    int vlen = strlen(val);
    while (pos % 4 != 0) buf[pos++] = 0;
    *(uint32_t *)(buf + pos) = vlen; pos += 4;
    memcpy(buf + pos, val, vlen + 1); pos += vlen + 1;
    return pos;
}

static int build_dbus_header_field_uint32(uint8_t *buf, int pos, uint8_t code, uint32_t val) {
    while (pos % 8 != 0) buf[pos++] = 0;
    buf[pos++] = code;
    buf[pos++] = 0x01; buf[pos++] = 'u'; buf[pos++] = 0x00;
    while (pos % 4 != 0) buf[pos++] = 0;
    *(uint32_t *)(buf + pos) = val; pos += 4;
    return pos;
}

static int build_dbus_header_field_sig(uint8_t *buf, int pos, const char *sig_val) {
    while (pos % 8 != 0) buf[pos++] = 0;
    buf[pos++] = DBUS_HEADER_FIELD_SIGNATURE;
    buf[pos++] = 0x01; buf[pos++] = 'g'; buf[pos++] = 0x00;
    int slen = strlen(sig_val);
    buf[pos++] = (uint8_t)slen;
    memcpy(buf + pos, sig_val, slen + 1); pos += slen + 1;
    return pos;
}

static int send_dbus_reply(int client_fd, uint32_t serial, uint32_t reply_serial,
                           const char *sender, const char *destination,
                           const char *body_str)
{
    uint8_t msg[512];
    int pos = 0;
    
    msg[pos++] = 'l';
    msg[pos++] = DBUS_TYPE_METHOD_RETURN;
    msg[pos++] = 0x01;
    msg[pos++] = 0x01;
    int body_len_off = pos; pos += 4;
    *(uint32_t *)(msg + pos) = serial; pos += 4;
    int fields_len_off = pos; pos += 4;
    int fields_start = pos;
    
    pos = build_dbus_header_field_uint32(msg, pos, DBUS_HEADER_FIELD_REPLY_SERIAL, reply_serial);
    pos = build_dbus_header_field_string(msg, pos, DBUS_HEADER_FIELD_SENDER, 's', sender);
    pos = build_dbus_header_field_string(msg, pos, DBUS_HEADER_FIELD_DESTINATION, 's', destination);
    if (body_str) {
        pos = build_dbus_header_field_sig(msg, pos, "s");
    }
    
    *(uint32_t *)(msg + fields_len_off) = pos - fields_start;
    while (pos % 8 != 0) msg[pos++] = 0;
    
    int body_start = pos;
    if (body_str) {
        int blen = strlen(body_str);
        *(uint32_t *)(msg + pos) = blen; pos += 4;
        memcpy(msg + pos, body_str, blen + 1); pos += blen + 1;
    }
    *(uint32_t *)(msg + body_len_off) = pos - body_start;
    
    return send_all(client_fd, (char *)msg, pos);
}

static int send_dbus_signal(int client_fd, uint32_t serial,
                            const char *path, const char *interface,
                            const char *member, const char *sender,
                            const char *destination, const char *body_str)
{
    uint8_t msg[512];
    int pos = 0;
    
    msg[pos++] = 'l';
    msg[pos++] = DBUS_TYPE_SIGNAL;
    msg[pos++] = 0x01;
    msg[pos++] = 0x01;
    int body_len_off = pos; pos += 4;
    *(uint32_t *)(msg + pos) = serial; pos += 4;
    int fields_len_off = pos; pos += 4;
    int fields_start = pos;
    
    pos = build_dbus_header_field_string(msg, pos, DBUS_HEADER_FIELD_PATH, 'o', path);
    pos = build_dbus_header_field_string(msg, pos, DBUS_HEADER_FIELD_INTERFACE, 's', interface);
    pos = build_dbus_header_field_string(msg, pos, DBUS_HEADER_FIELD_MEMBER, 's', member);
    pos = build_dbus_header_field_string(msg, pos, DBUS_HEADER_FIELD_SENDER, 's', sender);
    if (destination)
        pos = build_dbus_header_field_string(msg, pos, DBUS_HEADER_FIELD_DESTINATION, 's', destination);
    if (body_str)
        pos = build_dbus_header_field_sig(msg, pos, "s");
    
    *(uint32_t *)(msg + fields_len_off) = pos - fields_start;
    while (pos % 8 != 0) msg[pos++] = 0;
    
    int body_start = pos;
    if (body_str) {
        int blen = strlen(body_str);
        *(uint32_t *)(msg + pos) = blen; pos += 4;
        memcpy(msg + pos, body_str, blen + 1); pos += blen + 1;
    }
    *(uint32_t *)(msg + body_len_off) = pos - body_start;
    
    return send_all(client_fd, (char *)msg, pos);
}

static void close_ancillary_fds(AncillaryFds *afds) {
    for (int i = 0; i < afds->num_fds; i++) {
        close(afds->fds[i]);
    }
    afds->num_fds = 0;
}

// ---------- Buffer di lettura per-connessione ----------

typedef struct {
    uint8_t data[BUF_SIZE * 2];
    int len;
    AncillaryFds pending_fds[32];
    int pending_fds_count;
} ReadBuffer;

static void readbuf_init(ReadBuffer *rb) {
    rb->len = 0;
    rb->pending_fds_count = 0;
}

static int readbuf_fill(ReadBuffer *rb, int fd) {
    if (rb->len >= BUF_SIZE * 2) return -1;

    size_t read_len;
    if (rb->len < 16) {
        read_len = 16 - rb->len;
    } else {
        DBusRawHeader *hdr = (DBusRawHeader *)rb->data;
        if (hdr->endian != 'l' && hdr->endian != 'B') return -1;
        uint32_t msglen = align8(16 + hdr->header_fields_length) + hdr->body_length;
        if (msglen < 16 || msglen > BUF_SIZE * 2 || rb->len >= (int)msglen) return -1;
        read_len = msglen - rb->len;
    }
    
    AncillaryFds afds = {0};
    ssize_t n = recv_with_fds(fd, rb->data + rb->len, read_len, &afds);
    if (n <= 0) return -1;
    
    if (afds.num_fds > 0 && rb->pending_fds_count < 32) {
        rb->pending_fds[rb->pending_fds_count++] = afds;
    } else if (afds.num_fds > 0) {
        for (int i = 0; i < afds.num_fds; i++) close(afds.fds[i]);
    }
    
    rb->len += n;
    return n;
}

static int readbuf_has_message(ReadBuffer *rb) {
    if (rb->len < 16) return 0;
    
    DBusRawHeader *hdr = (DBusRawHeader *)rb->data;
    if (hdr->endian != 'l' && hdr->endian != 'B') return -1;
    
    uint32_t total_len = align8(12 + 4 + hdr->header_fields_length) + hdr->body_length;
    return (rb->len >= (int)total_len) ? (int)total_len : 0;
}

static int readbuf_extract(ReadBuffer *rb, uint8_t *out, int outsize, AncillaryFds *afds) {
    if (afds) { afds->num_fds = 0; }
    
    int msglen = readbuf_has_message(rb);
    if (msglen <= 0) return msglen;
    if (msglen > outsize) return -1;
    
    memcpy(out, rb->data, msglen);
    
    MsgFields mf;
    extract_msg_fields(out, msglen, &mf);
    if (afds && mf.has_unix_fds && mf.unix_fds > 0 && rb->pending_fds_count > 0) {
        *afds = rb->pending_fds[0];
        for (int i = 1; i < rb->pending_fds_count; i++) {
            rb->pending_fds[i-1] = rb->pending_fds[i];
        }
        rb->pending_fds_count--;
    }
    
    int remaining = rb->len - msglen;
    if (remaining > 0) {
        memmove(rb->data, rb->data + msglen, remaining);
    }
    rb->len = remaining;
    
    return msglen;
}

static int read_dbus_message_simple(int fd, uint8_t *buf, int bufsize, AncillaryFds *afds) {
    int hdr_size = 16;
    int total_read = 0;
    
    if (afds) afds->num_fds = 0;
    
    ssize_t n = recv_with_fds(fd, buf, bufsize, afds);
    if (n <= 0) return -1;
    total_read = n;
    
    if (total_read < hdr_size) {
        while (total_read < hdr_size) {
            n = read(fd, buf + total_read, hdr_size - total_read);
            if (n <= 0) return -1;
            total_read += n;
        }
    }
    
    DBusRawHeader *hdr = (DBusRawHeader *)buf;
    if (hdr->endian != 'l' && hdr->endian != 'B') return -1;
    
    uint32_t total_len = align8(12 + 4 + hdr->header_fields_length) + hdr->body_length;
    if ((int)total_len > bufsize) return -1;
    
    while (total_read < (int)total_len) {
        n = read(fd, buf + total_read, total_len - total_read);
        if (n <= 0) return -1;
        total_read += n;
    }
    return total_len;
}

static void* handle_client(void *arg) {
    int client_fd = *(int *)arg;
    free(arg);
    
    DBG("[+] Nuovo client connesso (fd=%d)\n", client_fd);
    
    if (authenticate_client(client_fd) < 0) {
        DBG("[-] Autenticazione client fallita\n");
        close(client_fd);
        return NULL;
    }
    DBG("[+] Client autenticato\n");
    
    int num_buses = route_count + 1;
    int *bus_fds = calloc(num_buses, sizeof(int));
    char **bus_names = calloc(num_buses, sizeof(char *));
    uint32_t *bus_serials = calloc(num_buses, sizeof(uint32_t));
    ReadBuffer *read_bufs = NULL;
    int epfd = -1;
    
    for (int i = 0; i < num_buses; i++) {
        bus_fds[i] = -1;
    }
    
    for (int i = 0; i < num_buses; i++) {
        const char *path = (i < route_count) ? routes[i].socket_path : default_socket_path;
        bus_fds[i] = connect_unix(path);
        if (bus_fds[i] < 0) {
            ERR("[-] Connessione a %s fallita: %s\n", path, strerror(errno));
            goto cleanup;
        }
        uid_t uid;
        int uid_set;
        if (i < route_count) {
            uid = routes[i].uid;
            uid_set = routes[i].uid_set;
        } else {
            uid = default_uid;
            uid_set = default_uid_set;
        }
        if (authenticate_to_bus(bus_fds[i], uid, uid_set) < 0) {
            ERR("[-] Autenticazione verso %s fallita\n", path);
            goto cleanup;
        }
        uint32_t ser;
        bus_names[i] = send_hello(bus_fds[i], &ser);
        if (!bus_names[i]) {
            ERR("[-] Hello verso %s fallita\n", path);
            goto cleanup;
        }
        bus_serials[i] = ser + 1;
        DBG("[+] Connesso a bus %s come %s\n", path, bus_names[i]);
    }
    
    const char *client_unique_name = bus_names[route_count];
    
    for (int i = 0; i < num_buses; i++) {
        uint8_t discard[BUF_SIZE];
        struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(bus_fds[i], &rfds);
        if (select(bus_fds[i] + 1, &rfds, NULL, NULL, &tv) > 0) {
            AncillaryFds afds = {0};
            read_dbus_message_simple(bus_fds[i], discard, BUF_SIZE, &afds);
            close_ancillary_fds(&afds);
            DBG("[*] Scartato NameAcquired da bus[%d]\n", i);
        }
    }
    
    int total_fds = 1 + num_buses;
    read_bufs = calloc(total_fds, sizeof(ReadBuffer));
    for (int i = 0; i < total_fds; i++) {
        readbuf_init(&read_bufs[i]);
    }
    
    struct {
        uint32_t client_serial;
        uint32_t proxy_serial;
        int bus_index;
    } pending[MAX_PENDING];
    int pending_count = 0;
    
    struct {
        uint32_t bus_serial;
        uint32_t client_serial;
        int bus_index;
    } pending_incoming[MAX_PENDING];
    int pending_incoming_count = 0;
    
    uint32_t client_out_serial = 0;
    
    epfd = epoll_create1(0);
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = client_fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, client_fd, &ev);
    
    for (int i = 0; i < num_buses; i++) {
        ev.data.fd = bus_fds[i];
        epoll_ctl(epfd, EPOLL_CTL_ADD, bus_fds[i], &ev);
    }
    
    uint8_t buf[BUF_SIZE];
    struct epoll_event events[MAX_CLIENTS];
    
    while (1) {
        int processed_buffered = 0;
        do {
            processed_buffered = 0;
            
            {
                ReadBuffer *rb = &read_bufs[0];
                AncillaryFds afds = {0};
                int msglen;
                while ((msglen = readbuf_extract(rb, buf, BUF_SIZE, &afds)) > 0) {
                    processed_buffered = 1;
                    MsgFields mf;
                    extract_msg_fields(buf, msglen, &mf);
                    uint8_t msg_type = buf[1];
                    
                    if (mf.interface && strcmp(mf.interface, "org.freedesktop.DBus") == 0 &&
                        mf.member && strcmp(mf.member, "Hello") == 0) {
                        uint32_t cs = get_serial(buf);
                        close_ancillary_fds(&afds);
                        send_dbus_reply(client_fd, ++client_out_serial, cs,
                                        "org.freedesktop.DBus", client_unique_name,
                                        client_unique_name);
                        DBG("[*] Hello intercettato, risposto con nome %s\n", client_unique_name);
                        send_dbus_signal(client_fd, ++client_out_serial,
                                         "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                         "NameAcquired", "org.freedesktop.DBus",
                                         client_unique_name, client_unique_name);
                        DBG("[*] Inviato NameAcquired(%s) al client\n", client_unique_name);
                        continue;
                    }
                    
                    int bus_idx = select_bus_index(mf.destination);
                    uint32_t orig_serial = get_serial(buf);
                    uint32_t new_serial = ++bus_serials[bus_idx];
                    set_serial(buf, new_serial);
                    
                    if (mf.has_sender) {
                        msglen = remove_header_field(buf, msglen, BUF_SIZE, DBUS_HEADER_FIELD_SENDER);
                        if (msglen < 0) { close_ancillary_fds(&afds); goto cleanup; }
                    }
                    
                    if ((msg_type == DBUS_TYPE_METHOD_RETURN || msg_type == DBUS_TYPE_ERROR) &&
                        mf.has_reply_serial) {
                        for (int i = 0; i < pending_incoming_count; i++) {
                            if (pending_incoming[i].client_serial == mf.reply_serial) {
                                modify_reply_serial_inplace(buf, msglen, pending_incoming[i].bus_serial);
                                bus_idx = pending_incoming[i].bus_index;
                                new_serial = ++bus_serials[bus_idx];
                                set_serial(buf, new_serial);
                                pending_incoming[i] = pending_incoming[--pending_incoming_count];
                                break;
                            }
                        }
                    }
                    
                    if (msg_type == DBUS_TYPE_METHOD_CALL && pending_count < MAX_PENDING) {
                        pending[pending_count].client_serial = orig_serial;
                        pending[pending_count].proxy_serial = new_serial;
                        pending[pending_count].bus_index = bus_idx;
                        pending_count++;
                    }
                    
                    if (send_all_with_fds(bus_fds[bus_idx], (char *)buf, msglen, &afds) < 0) {
                        close_ancillary_fds(&afds); goto cleanup;
                    }
                    close_ancillary_fds(&afds);
                    
                    DBG("[➔] client -> bus[%d] dest=%s serial %u->%u type=%d",
                           bus_idx, mf.destination ? mf.destination : "(null)",
                           orig_serial, new_serial, msg_type);
                    if (debug_enabled) {
                        if (mf.interface) printf(" iface=%s", mf.interface);
                        if (mf.member) printf(" member=%s", mf.member);
                        if (mf.has_unix_fds) printf(" unix_fds=%u", mf.unix_fds);
                        printf("\n");
                    }
                }
                if (msglen < 0) goto cleanup;
            }
            
            for (int bi = 0; bi < num_buses; bi++) {
                ReadBuffer *rb = &read_bufs[1 + bi];
                AncillaryFds afds = {0};
                int msglen;
                while ((msglen = readbuf_extract(rb, buf, BUF_SIZE, &afds)) > 0) {
                    processed_buffered = 1;
                    uint8_t msg_type = buf[1];
                    MsgFields mf;
                    extract_msg_fields(buf, msglen, &mf);
                    
                    if (msg_type == DBUS_TYPE_SIGNAL && mf.interface &&
                        strcmp(mf.interface, "org.freedesktop.DBus") == 0 &&
                        mf.member && (strcmp(mf.member, "NameAcquired") == 0 ||
                                      strcmp(mf.member, "NameLost") == 0)) {
                        DBG("[*] Scartato %s da bus[%d]\n", mf.member, bi);
                        close_ancillary_fds(&afds);
                        continue;
                    }
                    
                    if (msg_type == DBUS_TYPE_METHOD_RETURN || msg_type == DBUS_TYPE_ERROR) {
                        if (mf.has_reply_serial) {
                            uint32_t orig_client_serial = mf.reply_serial;
                            for (int i = 0; i < pending_count; i++) {
                                if (pending[i].proxy_serial == mf.reply_serial &&
                                    pending[i].bus_index == bi) {
                                    orig_client_serial = pending[i].client_serial;
                                    pending[i] = pending[--pending_count];
                                    break;
                                }
                            }
                            modify_reply_serial_inplace(buf, msglen, orig_client_serial);
                        }
                    }
                    
                    if (mf.destination && bus_names[bi]) {
                        if (mf.destination_len == strlen(bus_names[bi]) &&
                            memcmp(mf.destination, bus_names[bi], mf.destination_len) == 0) {
                            msglen = replace_header_string_field(buf, msglen, BUF_SIZE,
                                DBUS_HEADER_FIELD_DESTINATION, client_unique_name);
                            if (msglen < 0) { close_ancillary_fds(&afds); goto cleanup; }
                        }
                    }
                    
                    uint32_t original_bus_serial = get_serial(buf);
                    
                    set_serial(buf, ++client_out_serial);
                    
                    if (msg_type == DBUS_TYPE_METHOD_CALL && pending_incoming_count < MAX_PENDING) {
                        pending_incoming[pending_incoming_count].bus_serial = original_bus_serial;
                        pending_incoming[pending_incoming_count].client_serial = client_out_serial;
                        pending_incoming[pending_incoming_count].bus_index = bi;
                        pending_incoming_count++;
                    }
                    
                    if (send_all_with_fds(client_fd, (char *)buf, msglen, &afds) < 0) {
                        close_ancillary_fds(&afds); goto cleanup;
                    }
                    close_ancillary_fds(&afds);
                    
                    DBG("[←] bus[%d] -> client type=%d serial=%u",
                           bi, msg_type, client_out_serial);
                    if (debug_enabled) {
                        if (mf.has_reply_serial) printf(" reply_serial=%u", mf.reply_serial);
                        if (mf.interface) printf(" iface=%s", mf.interface);
                        if (mf.member) printf(" member=%s", mf.member);
                        if (mf.destination) printf(" dest=%.*s", mf.destination_len, mf.destination);
                        if (mf.has_unix_fds) printf(" unix_fds=%u", mf.unix_fds);
                        printf("\n");
                    }
                }
                if (msglen < 0) goto cleanup;
            }
        } while (processed_buffered);
        
        int nev = epoll_wait(epfd, events, MAX_CLIENTS, -1);
        if (nev < 0) { if (errno == EINTR) continue; break; }
        
        for (int e = 0; e < nev; e++) {
            int fd = events[e].data.fd;
            
            if (events[e].events & (EPOLLERR | EPOLLHUP)) {
                DBG("[-] Errore/hangup su fd=%d\n", fd);
                goto cleanup;
            }
            
            ReadBuffer *rb = NULL;
            if (fd == client_fd) {
                rb = &read_bufs[0];
            } else {
                for (int i = 0; i < num_buses; i++) {
                    if (fd == bus_fds[i]) {
                        rb = &read_bufs[1 + i];
                        break;
                    }
                }
            }
            if (!rb) continue;
            
            if (readbuf_fill(rb, fd) < 0) {
                DBG("[-] %s disconnesso (fd=%d)\n",
                    fd == client_fd ? "Client" : "Bus", fd);
                goto cleanup;
            }
        }
    }
    
cleanup:
    DBG("[*] Cleanup client fd=%d\n", client_fd);
    close(client_fd);
    if (epfd >= 0) close(epfd);
    for (int i = 0; i < num_buses; i++) {
        if (bus_fds[i] >= 0) close(bus_fds[i]);
        free(bus_names[i]);
    }
    if (read_bufs) {
        for (int i = 0; i < total_fds; i++) {
            for (int j = 0; j < read_bufs[i].pending_fds_count; j++) {
                close_ancillary_fds(&read_bufs[i].pending_fds[j]);
            }
        }
        free(read_bufs);
    }
    free(bus_fds);
    free(bus_names);
    free(bus_serials);
    return NULL;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Uso: %s -l <socket> -s <socket[@uid]> [-r <dest>:<socket[@uid]>]... [-d]\n"
        "\n"
        "Opzioni:\n"
        "  -l, --listen=PATH          Socket Unix su cui il proxy ascolta\n"
        "  -s, --session=PATH[@UID]   Socket del bus di sessione (default)\n"
        "  -r, --route=DEST:PATH[@UID]  Devia i messaggi per DEST verso PATH\n"
        "  -d, --debug                Abilita output di debug\n"
        "  -h, --help                 Mostra questo messaggio\n",
        prog);
}

static void parse_path_uid(char *spec, char **path, uid_t *uid, int *uid_set) {
    char *at = strrchr(spec, '@');
    if (at) {
        *at = '\0';
        *path = strdup(spec);
        *uid = (uid_t)atoi(at + 1);
        *uid_set = 1;
        *at = '@';
    } else {
        *path = strdup(spec);
        *uid = 0;
        *uid_set = 0;
    }
}

int main(int argc, char *argv[]) {
    static struct option long_options[] = {
        {"listen",   required_argument, 0, 'l'},
        {"session",  required_argument, 0, 's'},
        {"route",    required_argument, 0, 'r'},
        {"debug",    no_argument,       0, 'd'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "l:s:r:dh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'l':
                listen_socket_path = optarg;
                break;
            case 's':
                parse_path_uid(optarg, &default_socket_path, &default_uid, &default_uid_set);
                break;
            case 'r':
                if (route_count >= MAX_ROUTES) {
                    ERR("[-] Troppe rotte\n");
                    return EXIT_FAILURE;
                }
                char *sep = strchr(optarg, ':');
                if (!sep) {
                    ERR("[-] Formato rotta non valido: %s (atteso DEST:PATH[@UID])\n", optarg);
                    return EXIT_FAILURE;
                }
                routes[route_count].destination = strndup(optarg, sep - optarg);
                parse_path_uid(sep + 1, &routes[route_count].socket_path,
                               &routes[route_count].uid, &routes[route_count].uid_set);
                route_count++;
                break;
            case 'd':
                debug_enabled = 1;
                break;
            case 'h':
                usage(argv[0]);
                return EXIT_SUCCESS;
            default:
                usage(argv[0]);
                return EXIT_FAILURE;
        }
    }
    
    if (!listen_socket_path || !default_socket_path) {
        ERR("[-] Parametri -l e -s obbligatori\n\n");
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    
    unlink(listen_socket_path);
    
    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) { ERR("socket: %s\n", strerror(errno)); return EXIT_FAILURE; }
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, listen_socket_path, sizeof(addr.sun_path) - 1);
    
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ERR("bind: %s\n", strerror(errno)); return EXIT_FAILURE;
    }
    if (listen(server_fd, 16) < 0) {
        ERR("listen: %s\n", strerror(errno)); return EXIT_FAILURE;
    }
    
    LOG(stdout, "[*] DBus Proxy in ascolto su: %s\n", listen_socket_path);
    LOG(stdout, "[*] Bus sessione: %s\n", default_socket_path);
    for (int i = 0; i < route_count; i++) {
        LOG(stdout, "[*] Rotta: %s -> %s\n", routes[i].destination, routes[i].socket_path);
    }
       
    while (1) {
        int *client_fd = malloc(sizeof(int));
        *client_fd = accept(server_fd, NULL, NULL);
        if (*client_fd < 0) { free(client_fd); continue; }
        
        pthread_t tid;
        pthread_create(&tid, NULL, handle_client, client_fd);
        pthread_detach(tid);
    }
    
    close(server_fd);
    unlink(listen_socket_path);
    return EXIT_SUCCESS;
}