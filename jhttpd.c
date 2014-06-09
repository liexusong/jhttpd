/*
 * Copyright (c) 2013 - 2014, Liexusong <280259971@qq.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef linux
# include <linux/version.h>
# if LINUX_VERSION_CODE >= KERNEL_VERSION(2,2,0)
# define JHTTP_HAVE_SENDFILE 1
# endif
#endif

#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#ifdef JHTTP_HAVE_SENDFILE
# include <sys/sendfile.h>
#endif

#include "jk_thread_pool.h"
#include "jk_hash.h"
#include "jmalloc.h"

#define JHTTP_VERSION  "0.2"

#define JHTTP_OK    0
#define JHTTP_ERR   (-1)
#define JHTTP_DONE  1

#define JHTTP_IS_NULL(ret) ((ret) == NULL)

#define JHTTP_IS_OK(ret)   ((ret) == JHTTP_OK)
#define JHTTP_IS_ERR(ret)  ((ret) == JHTTP_ERR)
#define JHTTP_IS_DONE(ret) ((ret) == JHTTP_DONE)

#define JHTTP_DEFAULT_PORT    80
#define JHTTP_WORKER_THREADS  32

#define JHTTP_METHOD_UNKNOW   0
#define JHTTP_METHOD_GET      1
#define JHTTP_METHOD_HEAD     2
#define JHTTP_METHOD_POST     3

#define JHTTP_DEFAULT_RBUF_SIZE    512
#define JHTTP_DEFAULT_BUFF_INCR    128
#define JHTTP_BUFF_MAX_SIZE        2048

#define JHTTP_CR          '\r'
#define JHTTP_LF          '\n'
#define JHTTP_CRLF        "\r\n"
#define JHTTP_CRLFCRLF    "\r\n\r\n"


struct jhttp_connection;
typedef jhttp_connection_callback(struct jhttp_connection *c);

struct jhttp_base {
    int sock;
    int port;
    int threads;
    int daemon;
    char *root;
    char *default_charset;
    int timeout;
    jk_thread_pool_t *thread_pool;
    jk_hash_t *mimetype_table;
};

struct jhttp_connection {
    int sock;
    char *rbuf, *rpos, *rend;
    char uri[128];
    int method;
    jk_hash_t *headers;
    char *end_header;
    char *post_data;
    int post_len;
    jhttp_connection_callback *handler;
};

struct jhttp_mimetype {
    char *mime;
    char *exts;
};


int jhttp_connection_read_header(struct jhttp_connection *c);

static char error_403_page[] =
"<html>" JHTTP_CRLF
"<head><title>403 Forbidden</title></head>" JHTTP_CRLF
"<body bgcolor=\"white\">" JHTTP_CRLF
"<center><h1>403 Forbidden</h1></center>" JHTTP_CRLF
"<hr><center>JHTTPD</center>" JHTTP_CRLF
"</body>" JHTTP_CRLF
"</html>" JHTTP_CRLF
;

static char error_404_page[] =
"<html>" JHTTP_CRLF
"<head><title>404 Not Found</title></head>" JHTTP_CRLF
"<body bgcolor=\"white\">" JHTTP_CRLF
"<center><h1>404 Not Found</h1></center>" JHTTP_CRLF
"<hr><center>JHTTPD</center>" JHTTP_CRLF
"</body>" JHTTP_CRLF
"</html>" JHTTP_CRLF
;

static char error_500_page[] =
"<html>" JHTTP_CRLF
"<head><title>500 Internal Server Error</title></head>" JHTTP_CRLF
"<body bgcolor=\"white\">" JHTTP_CRLF
"<center><h1>500 Internal Server Error</h1></center>" JHTTP_CRLF
"<hr><center>JHTTPD</center>" JHTTP_CRLF
"</body>" JHTTP_CRLF
"</html>" JHTTP_CRLF
;

static struct jhttp_mimetype extension_map[] = {
    {"application/ogg",      "ogg"},
    {"application/pdf",      "pdf"},
    {"application/xml",      "xsl,xml"},
    {"application/xml-dtd",  "dtd"},
    {"application/xslt+xml", "xslt"},
    {"application/zip",      "zip"},
    {"audio/mpeg",           "mp2,mp3,mpga"},
    {"image/gif",            "gif"},
    {"image/jpeg",           "jpeg,jpe,jpg"},
    {"image/png",            "png"},
    {"text/css",             "css"},
    {"text/html",            "html,htm"},
    {"text/javascript",      "js"},
    {"text/plain",           "txt,asc"},
    {"video/mpeg",           "mpeg,mpe,mpg"},
    {"video/quicktime",      "qt,mov"},
    {"video/x-msvideo",      "avi"},
    {NULL,                   NULL}
};

static struct jhttp_base base;


int jhttp_set_nonblocking(int fd)
{
    int flags;

    if ((flags = fcntl(fd, F_GETFL, 0)) < 0 ||
         fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;
    return 0;
}


/*
 * read HTTP header was complete ?
 */
int jhttp_connection_header_complete(struct jhttp_connection *c)
{
    char *ptr = c->rbuf;
    enum {
        jhttp_state_0,  /* find "\r" */
        jhttp_state_1,  /* find "\n" */
        jhttp_state_2,  /* find "\r" */
        jhttp_state_3,  /* find "\n" */
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
    int tomove;

    jk_hash_free(c->headers);
    
    if (c->rpos > c->end_header) {
        tomove = c->rpos - c->end_header;
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


#define jhttp_is_letter(c)             \
    (((c) >= 'A' && (c) <= 'Z') ||     \
     ((c) >= 'a' && (c) <= 'z'))

int jhttp_connection_send_file(struct jhttp_connection *c)
{
    char buffer[2048], date_buf[128];
    time_t now;
    struct tm tm;
    struct stat stbuf;
    int fd = -1;
    int send_header_only = 0;
    int wbytes, nwrite = 0, n;
    off_t offset, _offset;
    int sendmax;
    char *keepalive;
    fd_set set;
    struct timeval tv;
    int result;

    /* current datetime */
    now = time((time_t *)0);
    strftime(date_buf, sizeof(date_buf), "%a, %d %b %Y %H:%M:%S GMT",
                                                           gmtime_r(&now, &tm));

    if (stat(c->uri, &stbuf) == -1) {
        wbytes = sprintf(buffer, "HTTP/1.1 404 Not Found" JHTTP_CRLF
                                 "Date: %s" JHTTP_CRLF
                                 "Content-Length: %d" JHTTP_CRLF
                                 "Server: JHTTPD" JHTTP_CRLFCRLF "%s",
                                 date_buf, sizeof(error_404_page) - 1,
                                 error_404_page);

        send_header_only = 1;

    } else if (S_ISDIR(stbuf.st_mode)) {

        wbytes = sprintf(buffer, "HTTP/1.1 403 Forbidden" JHTTP_CRLF
                                 "Date: %s" JHTTP_CRLF
                                 "Content-Length: %d" JHTTP_CRLF
                                 "Server: JHTTPD" JHTTP_CRLFCRLF "%s", 
                                 date_buf, sizeof(error_403_page) - 1,
                                 error_403_page);

        send_header_only = 1;

    } else {
        char *last_modified;
        char modified_buf[128];
        char extbuf[16], *ext;
        char *mimetype = "text/plain";
        int len;

        do {

            strftime(modified_buf, sizeof(modified_buf),
                        "%a, %d %b %Y %H:%M:%S GMT", gmtime(&(stbuf.st_mtime)));

            if (jk_hash_find(c->headers, "if-modified-since",
                sizeof("if-modified-since")-1, (void **)&last_modified)
                == JK_HASH_OK)
            {
                struct tm tm;
    
                if (strptime(last_modified, "%a, %d %b %Y %H:%M:%S %Z", &tm)
                    != NULL)
                {
                    time_t lmt = mktime(&tm) + 3600 * 8; /* fix 8 hours */

                    if ((int)lmt >= (int)stbuf.st_mtime) {
                        wbytes = sprintf(buffer,
                                     "HTTP/1.1 304 Not Modified" JHTTP_CRLF
                                     "Date: %s" JHTTP_CRLF
                                     "Last-Modified: %s" JHTTP_CRLF
                                     "Server: JHTTPD" JHTTP_CRLFCRLF,
                                     date_buf, modified_buf);

                        send_header_only = 1;

                        break;
                    }
                }
            }
    
            /* find the mime type */
            for (ext = c->uri + 1; *ext && *ext != '.'; ext++);
    
            if (*ext == '.') { /* found extension */
    
                for (len = 0, ext += 1; jhttp_is_letter(*ext); ext++) {
                    if (*ext >= 'A' && *ext <= 'Z') { /* upper to lower */
                        extbuf[len++] = *ext + ('a' - 'Z');
                    } else {
                        extbuf[len++] = *ext;
                    }
                }
    
                if (len > 0) {
                    jk_hash_find(base.mimetype_table, extbuf, len,
                                 (void **)&mimetype);
                }
            }
    
            wbytes = sprintf(buffer, "HTTP/1.1 200 OK" JHTTP_CRLF
                                     "Content-Length: %d" JHTTP_CRLF
                                     "Content-Type: %s; charset=%s" JHTTP_CRLF
                                     "Last-Modified: %s" JHTTP_CRLF
                                     "Date: %s" JHTTP_CRLF
                                     "Server: JHTTPD" JHTTP_CRLFCRLF,
                                     (int)stbuf.st_size, mimetype,
                                     base.default_charset, modified_buf,
                                     date_buf);
    
            if (c->method != JHTTP_METHOD_HEAD) {
                fd = open(c->uri, O_RDONLY);
                if (JHTTP_IS_ERR(fd)) {
                    wbytes = sprintf(buffer,
                                "HTTP/1.1 500 Internal Server Error" JHTTP_CRLF
                                "Date: %s" JHTTP_CRLF
                                "Content-Length: %d" JHTTP_CRLF
                                "Server: JHTTPD" JHTTP_CRLFCRLF "%s",
                                date_buf, sizeof(error_500_page) - 1,
                                error_500_page);

                    send_header_only = 1;
                }
            }

        } while (0);
    }

    tv.tv_sec = base.timeout / 1000;
    tv.tv_usec = (base.timeout % 1000) * 1000;

    /* send header to client */
    while (nwrite < wbytes) {

        FD_ZERO(&set);
        FD_SET(c->sock, &set);

        result = select(c->sock + 1, NULL, &set, NULL, &tv);
        if (result <= 0) {
            goto eflag;
        }

        n = write(c->sock, buffer + nwrite, wbytes - nwrite);
        switch (n) {
        case 0: /* connection was closed */
            goto eflag;
            break;
        case -1:
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                goto eflag;
            }
            break;
        default:
            nwrite += n;
            break;
        }
    }

    if (send_header_only || c->method == JHTTP_METHOD_HEAD) {
        return JHTTP_DONE;
    }


#ifdef JHTTP_HAVE_SENDFILE

    offset = 0;
    wbytes = (int)stbuf.st_size;

    for ( ;; ) {

        sendmax = wbytes > (1 << 20) ? (1 << 20) : wbytes;
        _offset = offset;

        FD_ZERO(&set);
        FD_SET(c->sock, &set);

        result = select(c->sock + 1, NULL, &set, NULL, &tv);
        if (result <= 0) {
            goto eflag;
        }

        n = sendfile(c->sock, fd, &_offset, sendmax);
        switch (n) {
        case 0:
            goto eflag;
            break;
        case -1:
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                goto eflag;
            }
            break;
        default:
            offset += n;
            wbytes -= n;
            break;
        }

        if (wbytes <= 0) {
            break;
        }
    }

#else

    for ( ;; ) {

        FD_ZERO(&set);
        FD_SET(c->sock, &set);

        result = select(c->sock + 1, NULL, &set, NULL, &tv);
        if (result <= 0) {
            goto eflag;
        }

        nwrite = 0;

        wbytes = read(fd, buffer, 2048);
        if (wbytes <= 0) {
            break;
        }

        while (nwrite < wbytes) {
            n = write(c->sock, buffer + nwrite, wbytes - nwrite);
            switch (n) {
            case 0: /* connection was closed */
                goto eflag;
                break;
            case -1:
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    goto eflag;
                }
                break;
            default:
                nwrite += n;
                break;
            }
        }
    }

#endif

    close(fd);


    if (jk_hash_find(c->headers, "connection",
        sizeof("connection")-1, (void **)&keepalive) == JK_HASH_OK)
    {
        if (!strncasecmp("keep-alive", keepalive, sizeof("keep-alive")-1)) {
            jhttp_reset_connection(c);
            return JHTTP_OK;
        }
    }

    return JHTTP_DONE;

eflag:
    if (!JHTTP_IS_ERR(fd)) {
        close(fd);
    }
    return JHTTP_ERR;
}


int jhttp_connection_read_post(struct jhttp_connection *c)
{
    fd_set set;
    struct timeval tv;
    int result;
    int nbytes = c->post_len, rbytes = 0, n;

    c->post_data = jmalloc(c->post_len + 1); /* include nil */
    if (c->post_data == NULL) {
        return JHTTP_ERR;
    }

    if (c->rpos - 1 > c->end_header) { /* post data may be readed */
        int remain = c->rpos - c->end_header - 1;
        int ncopy = remain > nbytes ? nbytes : remain;

        memcpy(c->post_data, c->end_header + 1, ncopy);

        c->end_header += ncopy;
        nbytes -= ncopy;
        rbytes += ncopy;
    }

    while (nbytes > 0) {
        tv.tv_sec = base.timeout / 1000;
        tv.tv_usec = (base.timeout % 1000) * 1000;

        FD_ZERO(&set);
        FD_SET(c->sock, &set);

        result = select(c->sock + 1, &set, NULL, NULL, &tv);
        if (result <= 0) {
            return JHTTP_DONE;
        }

        n = read(c->sock, c->post_data + rbytes, nbytes);
        if (nbytes == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
            fprintf(stderr, "Error: failed to read data from connection\n");
            return JHTTP_ERR;
        } else if (nbytes == 0) {
            return JHTTP_DONE;
        }

        rbytes += n;
        nbytes -= n;
    }

    c->post_data[c->post_len] = '\0';

    c->handler = jhttp_connection_send_file;

    return JHTTP_OK;
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
                } else if (!strncasecmp(found, "POST", 4)) {
                    c->method = JHTTP_METHOD_POST;
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

                if (found[0] != '/') {
                    c->uri[0] = '\0';
                } else {
                    c->uri[0] = '.';
                    memcpy(c->uri + 1, found, len);
                    c->uri[len + 1] = '\0';
                }

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

    if (c->method == JHTTP_METHOD_POST) {
        int post_len;
        char *ptr;

        if (jk_hash_find(c->headers, "content-length",
            sizeof("content-length")-1, (void **)&ptr) == JK_HASH_OK)
        {
            post_len = atoi(ptr);
            if (post_len > 0) {
                c->post_len = post_len;
                c->handler = jhttp_connection_read_post;
                return JHTTP_OK;
            }
        }
    }

    c->handler = jhttp_connection_send_file;

    return JHTTP_OK;
}


int jhttp_connection_read_header(struct jhttp_connection *c)
{
    fd_set set;
    struct timeval tv;
    int remain, nbytes, result;

    for ( ;; ) {

        remain = c->rend - c->rpos;

        if (remain <= 0) {
            char *temp;
            int osize = c->rend - c->rbuf;
            int nsize = osize + JHTTP_DEFAULT_BUFF_INCR;
            int rpos = c->rpos - c->rbuf;

            if (nsize > JHTTP_BUFF_MAX_SIZE) {
                fprintf(stderr, "Error: request http header too big\n");
                return JHTTP_ERR;
            }

            temp = jrealloc(c->rbuf, nsize);
            if (JHTTP_IS_NULL(temp)) {
                fprintf(stderr, "Error: not enough memory to realloc buffer\n");
                return JHTTP_ERR;
            }

            c->rbuf = temp;
            c->rpos = c->rbuf + rpos;
            c->rend = c->rbuf + nsize;

            remain = c->rend - c->rpos;
        }

        tv.tv_sec = base.timeout / 1000;
        tv.tv_usec = (base.timeout % 1000) * 1000;

        FD_ZERO(&set);
        FD_SET(c->sock, &set);

        result = select(c->sock + 1, &set, NULL, NULL, &tv);
        if (result <= 0) {
            return JHTTP_DONE;
        }

        nbytes = read(c->sock, c->rpos, remain);
        if (nbytes == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
            fprintf(stderr, "Error: failed to read data from connection\n");
            return JHTTP_ERR;
        } else if (nbytes == 0) {
            return JHTTP_DONE;
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

    c = jmalloc(sizeof(*c));
    if (JHTTP_IS_NULL(c)) {
        return NULL;
    }

    c->sock = sock;
    c->method = JHTTP_METHOD_UNKNOW;
    c->headers = jk_hash_new(0, NULL, NULL);
    c->end_header = NULL;
    c->post_data = NULL;
    c->post_len = 0;
    c->handler = &jhttp_connection_read_header;

    c->rbuf = jmalloc(JHTTP_DEFAULT_RBUF_SIZE);
    if (JHTTP_IS_NULL(c->rbuf)) {
        jk_hash_free(c->headers);
        jfree(c);
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
    jfree(c->rbuf);
    if (c->post_data) {
        jfree(c->post_data);
    }
    jfree(c);
    return;
}


void jhttp_init_mimetype_table()
{
    struct jhttp_mimetype *type = extension_map;
    char *skey, *ekey;

    while (type->mime != NULL) {
        skey = ekey = type->exts;

        while (*ekey) {

            if (*ekey == ',') {
                jk_hash_insert(base.mimetype_table, skey,
                               ekey - skey, type->mime, 1);

                skey = ekey + 1;
            }
            ekey++;
        }

        jk_hash_insert(base.mimetype_table, skey,
                       ekey - skey, type->mime, 1);

        type++;
    }
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

    if (jhttp_set_nonblocking(base.sock) == -1) {
        close(base.sock);
        fprintf(stderr, "Fatal: failed to set socket nonblocking\n");
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(base.port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(base.sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        close(base.sock);
        fprintf(stderr, "Fatal: failed to bind socket\n");
        return -1;
    }

    if (listen(base.sock, 1024) == -1) {
        close(base.sock);
        fprintf(stderr, "Fatal: failed to listen socket\n");
        return -1;
    }

    base.thread_pool = jk_thread_pool_new(base.threads);
    if (JHTTP_IS_NULL(base.thread_pool)) {
        fprintf(stderr, "Fatal: failed to create thread pool\n");
        return -1;
    }

    base.mimetype_table = jk_hash_new(0, NULL, NULL);
    if (JHTTP_IS_NULL(base.mimetype_table)) {
        fprintf(stderr, "Fatal: failed to create mimetype table\n");
        return -1;
    }

    jhttp_init_mimetype_table();

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


void jhttp_timer()
{
    int mem = jmalloc_usage_memory();

    if (mem > 1024 * 1024 * 10) {
        fprintf(stderr, "Notice: usage memory %d bytes > 10MB\n", mem);
    }
}


void jhttp_main_loop()
{
    fd_set set;
    struct timeval tv;
    int sock;
    socklen_t len;
    struct sockaddr addr;
    struct jhttp_connection *c;
    int ret;

    for ( ;; ) {

        FD_ZERO(&set);
        FD_SET(base.sock, &set);

        tv.tv_sec = 10;
        tv.tv_usec = 0;

        if (select(base.sock + 1, &set, NULL, NULL, &tv) == -1) {
            fprintf(stderr, "Error: select(socket) failed\n");
            continue;
        }

        jhttp_timer();

        for ( ;; ) {

            sock = accept(base.sock, &addr, &len);
            if (sock == -1) { /* no more client to accept */
                break;
            }
    
            if (jhttp_set_nonblocking(sock) == -1) {
                fprintf(stderr, "Error: failed to set socket to nonblocking\n");
                close(sock);
                continue;
            }
    
            c = jhttp_get_connection(sock);
            if (JHTTP_IS_NULL(c)) {
                fprintf(stderr, "Error: failed to get connection and exiting\n");
                close(sock);
                continue;
            }
    
            ret = jk_thread_pool_push(base.thread_pool,
                                      &jhttp_connection_loop, c, NULL);
            if (JHTTP_IS_ERR(ret)) {
                fprintf(stderr, "Error: failed to process connection and exiting\n");
                jhttp_close_connection(c);
                continue;
            }
        }
    }

    return;
}


static void jhttp_usage()
{
    fprintf(stderr, "JHTTPD v%s Usage: ./jhttpd [OPTION] ...\n\n", JHTTP_VERSION);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "-d, --daemon        Daemon mode\n");
    fprintf(stderr, "-p, --port=PORT     Server listen port, default 80\n");
    fprintf(stderr, "-t, --threads=NUMS  Worker thread numbers\n");
    fprintf(stderr, "-r, --root=PATH     The server root path\n");
    fprintf(stderr, "-s, --charset=STR   Default charset\n");
    fprintf(stderr, "-o, --timeout=MSEC  Connection timeout msec\n");
    fprintf(stderr, "-h, --help          Show the help\n");
    exit(0);
}


void jhttp_default_options()
{
    base.port = JHTTP_DEFAULT_PORT;
    base.daemon = 0;
    base.threads = JHTTP_WORKER_THREADS;
    base.root = "/var/www";
    base.default_charset = "UTF-8";
    base.timeout = 5000;
}


int jhttp_options(int argc, char *argv[])
{
    int opt;
    struct option lopts[] = {
        {"port",        1,  NULL,  'p'},
        {"daemon",      0,  NULL,  'd'},
        {"threads",     0,  NULL,  't'},
        {"root",        0,  NULL,  'r'},
        {"charset",     0,  NULL,  's'},
        {"timeout",     0,  NULL,  'o'},
        {"help",        0,  NULL,  'h'},
        {NULL,          0,  NULL,    0}
    };

    while ((opt = getopt_long(argc, argv, "p:dt:r:s:o:h", lopts, NULL)) != -1) {
        switch (opt) {
        case 'p':
            base.port = atoi(optarg);
            if (base.port < 1 || base.port > 65535) {
                fprintf(stderr, "Fatal: input port number %d invaild, "
                                "must between 1 - 65535.\n", base.port);
                return -1;
            }
            break;
        case 'd':
            base.daemon = 1;
            break;
        case 't':
            base.threads = atoi(optarg);
            if (base.threads <= 0) {
                base.threads = 10;
            }
            break;
        case 'r':
            base.root = strdup(optarg);
            break;
        case 's':
            base.default_charset = strdup(optarg);
            break;
        case 'o':
            base.timeout = atoi(optarg);
            if (base.timeout < 0) {
                base.timeout = 5000;
            }
            break;
        case 'h':
        default:
            jhttp_usage();
            break;
        }
    }
}


void jhttp_daemon()
{
    int fd;

    if (fork() != 0) {
        exit(0);
    }

    setsid();

    if ((fd = open("/dev/null", O_RDWR, 0)) != -1) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO) close(fd);
    }
}


int main(int argc, char *argv[])
{
    struct sigaction sa;

    jhttp_default_options();
    jhttp_options(argc, argv);

    if (base.daemon) {
        jhttp_daemon();
    }

    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;

    if (sigemptyset(&sa.sa_mask) == -1 ||
        sigaction(SIGPIPE, &sa, 0) == -1)
    {
        fprintf(stderr, "Fatal: failed to ignore SIGPIPE; sigaction");
        exit(1);
    }

    if (chdir(base.root) == -1) {
        fprintf(stderr, "Fatal: failed to chdir(%s)\n", base.root);
        exit(1);
    }

    if (JHTTP_IS_ERR(jhttp_base_init())) {
        exit(1);
    }

    jhttp_main_loop();

    close(base.sock);
    jk_hash_free(base.mimetype_table);
    jk_thread_pool_destroy(base.thread_pool);

    exit(0);
}

