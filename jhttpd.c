#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>

#include "jk_thread_pool.h"
#include "jk_hash.h"

#define JHTTP_OK    0
#define JHTTP_ERR   (-1)
#define JHTTP_DONE  1

#define JHTTP_IS_NULL(ret) ((ret) == NULL)

#define JHTTP_IS_OK(ret)   ((ret) == JHTTP_OK)
#define JHTTP_IS_ERR(ret)  ((ret) == JHTTP_ERR)
#define JHTTP_IS_DONE(ret) ((ret) == JHTTP_DONE)

#define JHTTP_DEFAULT_PORT    8080
#define JHTTP_WORKER_THREADS  32

#define JHTTP_METHOD_UNKNOW   0
#define JHTTP_METHOD_GET      1
#define JHTTP_METHOD_HEAD     2

#define JHTTP_DEFAULT_RBUF_SIZE    512
#define JHTTP_DEFAULT_BUFF_INCR    128
#define JHTTP_BUFF_MAX_SIZE        2048

#define JHTTP_CR    '\r'
#define JHTTP_LF    '\n'
#define JHTTP_CRLF  "\r\n"

struct jhttp_connection;
typedef jhttp_connection_callback(struct jhttp_connection *c);

struct jhttp_base {
    int sock;
    jk_thread_pool_t *thread_pool;
};

struct jhttp_connection {
    int sock;
    char *rbuf, *rpos, *rend;
    char uri[128];
    int method;
    jk_hash_t *headers;
    char *end_header;
    jhttp_connection_callback *handler;
};


int jhttp_connection_read_header(struct jhttp_connection *c);

static struct jhttp_base base;


int jhttp_connection_header_complete(struct jhttp_connection *c)
{
    char *ptr = c->rbuf;
    enum {
        jhttp_state_0,
        jhttp_state_1,
        jhttp_state_2,
        jhttp_state_3,
    } state = jhttp_state_0;

    while (ptr <= c->rpos) {
        switch (state) {
        case jhttp_state_0:
            if (*ptr == JHTTP_CR) {
                state = jhttp_state_1;
            } else {
                state = jhttp_state_0;
            }
            break;
        case jhttp_state_1:
            if (*ptr == JHTTP_LF) {
                state = jhttp_state_2;
            } else {
                state = jhttp_state_0;
            }
            break;
        case jhttp_state_2:
            if (*ptr == JHTTP_CR) {
                state = jhttp_state_3;
            } else {
                state = jhttp_state_0;
            }
            break;
        case jhttp_state_3:
            if (*ptr == JHTTP_LF) {
                c->end_header = ptr;
                return 0;
            } else {
                state = jhttp_state_0;
            }
            break;
        }
        ptr++;
    }
    return -1;
}


void jhttp_reset_connection(struct jhttp_connection *c)
{
    jk_hash_free(c->headers);
    
    if (c->rpos > c->end_header) {
        int tomove = c->rpos - c->end_header;
        memmove(c->rbuf, c->end_header + 1, tomove);
        c->rpos = c->rbuf + tomove;
    } else {
        c->rpos = c->rbuf;
    }

    c->method = JHTTP_METHOD_UNKNOW;
    c->headers = jk_hash_new(0, NULL, NULL);
    c->end_header = NULL;
    c->handler = &jhttp_connection_read_header;

    return;
}


int jhttp_connection_send_file(struct jhttp_connection *c)
{
    char buffer[2048];
    struct stat stbuf;
    FILE *fp;
    int send_header_only = 0;
    int wbytes, nwrite = 0, n;
    char *keepalive;

    if (stat(c->uri, &stbuf) == -1) {
        wbytes = sprintf(buffer, "HTTP/1.1 404 Not Found\r\n\r\n");
        send_header_only = 1;

    } else if (S_ISDIR(stbuf.st_mode)) {
        wbytes = sprintf(buffer, "HTTP/1.1 403 Forbidden\r\n\r\n");
        send_header_only = 1;

    } else {

        fp = fopen(c->uri, "r");

        if (JHTTP_IS_NULL(fp)) {
            wbytes = sprintf(buffer, "HTTP/1.1 500 Internal Server Error\r\n\r\n");
            send_header_only = 1;

        } else {
            wbytes = sprintf(buffer, "HTTP/1.1 200 OK\r\n"
                                     "Content-Length: %d\r\n\r\n", stbuf.st_size);
        }
    }

    while (nwrite < wbytes) {
        n = write(c->sock, buffer + nwrite, wbytes - nwrite);
        if (n > 0) {
            nwrite += n;
        }
    }

    if (send_header_only) {
        return JHTTP_DONE;
    }

    while (!feof(fp)) {

        fread(buffer, 2048, 1, fp);

        nwrite = 0;
        wbytes = strlen(buffer);

        while (nwrite < wbytes) {

            n = write(c->sock, buffer + nwrite, wbytes - nwrite);
            if (n > 0) {
                nwrite += n;
            }
        }
    }

    if (jk_hash_find(c->headers, "connection",
        sizeof("connection")-1, (void **)&keepalive) == JK_HASH_OK)
    {
        if (!strncasecmp("keep-alive", keepalive, sizeof("keep-alive")-1)) {
            jhttp_reset_connection(c);
            return JHTTP_OK;
        }
    }

    return JHTTP_DONE;
}


char *
jhttp_connection_parse_request_line(struct jhttp_connection *c)
{
    char *found, *current;
    enum {
        jhttp_get_method_state,
        jhttp_get_uri_state,
        jhttp_get_version_state,
    } state = jhttp_get_method_state;

    for (found = current = c->rbuf;
         current < c->end_header;
         current++)
    {
        switch (state) {
        case jhttp_get_method_state:

            if (*current == ' ') {
                if (!strncasecmp(found, "GET", 3)) {
                    c->method = JHTTP_METHOD_GET;
                } else if (!strncasecmp(found, "HEAD", 4)) {
                    c->method = JHTTP_METHOD_HEAD;
                } else {
                    return NULL;
                }
                state = jhttp_get_uri_state;
                found = current + 1;
            }
            break;

        case jhttp_get_uri_state:

            if (*current == ' ') {
                int len = (current - found > 126 ? 126 : current - found);

                c->uri[0] = '.';
                memcpy(c->uri + 1, found, len);
                c->uri[len + 1] = '\0';

                state = jhttp_get_version_state;
                found = current + 1;
            }
            break;

        case jhttp_get_version_state:
            if (*current == JHTTP_LF) {
                return current + 1;
            }
            break;
        }
    }

    return NULL;
}


void jhttp_tolower(char *str, int len)
{
    int fix = 'a' - 'A';
    int i;

    for (i = 0; i < len; i++) {
        if (str[i] >= 'A' && str[i] <= 'Z') {
            str[i] += fix;
        }
    }
    return;
}


#define jhttp_is_space(c)  \
    ((c) == ' ' || (c) == JHTTP_CR || (c) == JHTTP_LF || (c) == '\t')

int jhttp_connection_parse_header(struct jhttp_connection *c)
{
    char *start, *current;
    char *key, *val;
    int klen;
    enum {
        jhttp_header_none1_state,
        jhttp_header_key_state,
        jhttp_header_none2_state,
        jhttp_header_val_state
    } state = jhttp_header_none1_state;

    start = current = jhttp_connection_parse_request_line(c);

    if (JHTTP_IS_NULL(current)) { /* not found request line */
        return JHTTP_ERR;
    }

    for (/* void */; current <= c->end_header; current++) {

        switch (state) {
        case jhttp_header_none1_state:
            if (!jhttp_is_space(*current)) { /* skip space */
                key = current;
                state = jhttp_header_key_state;
            }
            break;

        case jhttp_header_key_state:
            if (*current == ':' || jhttp_is_space(*current)) {
                klen = current - key;
                state = jhttp_header_none2_state;
            }
            break;

        case jhttp_header_none2_state:
            if (!jhttp_is_space(*current)) {
                val = current;
                state = jhttp_header_val_state;
            }
            break;

        case jhttp_header_val_state:
            if (*current == JHTTP_LF) {
                char *ptr = current - 1;

                while (ptr >= start) { /* rtrim space */
                    if (jhttp_is_space(*ptr)) {
                        *ptr = '\0';
                    } else {
                        break;
                    }
                }
                *current = '\0';

                if (klen > 0) {
                    jhttp_tolower(key, klen);
                    jk_hash_insert(c->headers, key, klen, val, 0);
                }

                state = jhttp_header_none1_state;
            }
            break;
        }
    }

    c->handler = jhttp_connection_send_file;

    return JHTTP_OK;
}


int jhttp_connection_read_header(struct jhttp_connection *c)
{
    int remain, nbytes;

    for ( ;; ) {

        remain = c->rend - c->rpos;

        if (remain <= 0) {
            char *temp;
            int osize = c->rend - c->rbuf;
            int nsize = osize + JHTTP_DEFAULT_BUFF_INCR;
            int rpos = c->rpos - c->rbuf;

            if (nsize > JHTTP_BUFF_MAX_SIZE) {
                fprintf(stderr, "Notcie: request http header too big\n");
                return JHTTP_ERR;
            }

            temp = realloc(c->rbuf, nsize);
            if (JHTTP_IS_NULL(temp)) {
                fprintf(stderr, "Notcie: not enough memory to realloc read buffer\n");
                return JHTTP_ERR;
            }

            c->rbuf = temp;
            c->rpos = c->rbuf + rpos;
            c->rend = c->rbuf + nsize;

            remain = c->rend - c->rpos;
        }

        nbytes = read(c->sock, c->rpos, remain);
        if (nbytes == -1) {
            fprintf(stderr, "Notcie: failed to read data from connection\n");
            return JHTTP_ERR;
        } else if (nbytes == 0) {
            fprintf(stderr, "Notcie: connection was closed, socket(%d)\n", c->sock);
            return JHTTP_ERR;
        }

        c->rpos += nbytes;

        if (JHTTP_IS_OK(jhttp_connection_header_complete(c))) {
            return jhttp_connection_parse_header(c);
        }
    }
}

struct jhttp_connection *jhttp_get_connection(int sock)
{
    struct jhttp_connection *c;

    c = malloc(sizeof(*c));
    if (JHTTP_IS_NULL(c)) {
        return NULL;
    }

    c->sock = sock;
    c->method = JHTTP_METHOD_UNKNOW;
    c->headers = jk_hash_new(0, NULL, NULL);
    c->end_header = NULL;
    c->handler = &jhttp_connection_read_header;

    c->rbuf = malloc(JHTTP_DEFAULT_RBUF_SIZE);
    if (JHTTP_IS_NULL(c->rbuf)) {
        jk_hash_free(c->headers);
        free(c);
        return NULL;
    }
    c->rpos = c->rbuf;
    c->rend = c->rbuf + JHTTP_DEFAULT_RBUF_SIZE;

    return c;
}

void jhttp_close_connection(struct jhttp_connection *c)
{
    close(c->sock);
    jk_hash_free(c->headers);
    free(c->rbuf);
    free(c);
    return;
}

int jhttp_base_init()
{
    struct sockaddr_in addr;
    struct linger ling = {0, 0};
    int flags = 1;

    base.sock = socket(AF_INET, SOCK_STREAM, 0);
    if (base.sock == -1) {
        fprintf(stderr, "Fatal: failed to create socket\n");
        return -1;
    }

    setsockopt(base.sock, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags));
    setsockopt(base.sock, SOL_SOCKET, SO_KEEPALIVE, &flags, sizeof(flags));
    setsockopt(base.sock, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));
#if !defined(TCP_NOPUSH)
    setsockopt(base.sock, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof(flags));
#endif

    addr.sin_family = AF_INET;
    addr.sin_port = htons(JHTTP_DEFAULT_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(base.sock, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
        close(base.sock);
        fprintf(stderr, "Fatal: failed to bind socket\n");
        return -1;
    }

    if (listen(base.sock, 1024) == -1) {
        close(base.sock);
        fprintf(stderr, "Fatal: failed to listen socket\n");
        return -1;
    }

    base.thread_pool = jk_thread_pool_new(JHTTP_WORKER_THREADS);
    if (JHTTP_IS_NULL(base.thread_pool)) {
        fprintf(stderr, "Fatal: failed to create thread pool\n");
        return -1;
    }

    return 0;
}


void jhttp_connection_loop(void *arg)
{
    struct jhttp_connection *c = arg;
    int ret;

    for ( ;; ) {

        ret = c->handler(c);

        if (JHTTP_IS_ERR(ret) || JHTTP_IS_DONE(ret)) {
            jhttp_close_connection(c);
            return;
        }
    }
}


void jhttp_main_loop()
{
    int sock;
    socklen_t len;
    struct sockaddr addr;
    struct jhttp_connection *c;
    int ret;

    for ( ;; ) {

        sock = accept(base.sock, &addr, &len);
        if (sock == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                fprintf(stderr, "Notice: failed to accept client connection\n");
            }
            continue;
        }

        c = jhttp_get_connection(sock);
        if (JHTTP_IS_NULL(c)) {
            fprintf(stderr, "Fatal: failed to get connection and exiting\n");
            close(sock);
            break;
        }

        ret = jk_thread_pool_push(base.thread_pool,
                                  &jhttp_connection_loop, c, NULL);
        if (JHTTP_IS_ERR(ret)) {
            fprintf(stderr, "Fatal: failed to process connection and exiting\n");
            jhttp_close_connection(c);
            break;
        }
    }

    return;
}


int main()
{
    chdir("./");

    if (JHTTP_IS_ERR(jhttp_base_init())) {
        exit(1);
    }

    jhttp_main_loop();

    exit(0);
}

