#include <stdint.h>
#include <stdio.h>
#include "core/proxy.h"

#if defined(PULSE_HAVE_HYSTERIA2)

#include <stdlib.h>
#include <string.h>
#if defined(__ANDROID__)
#include <errno.h>
#endif
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <nghttp3/nghttp3.h>

#define HY2_AUTH_PADDING_MIN 256
#define HY2_AUTH_PADDING_MAX 2048
#define HY2_TCP_PADDING_MIN 64
#define HY2_TCP_PADDING_MAX 512
#define HY2_STATUS_AUTH_OK 233
#define HY2_FRAME_TYPE_TCP_REQUEST 0x401
#define HY2_MAX_RESPONSE_MSG 2048
#define HY2_MAX_PADDING 4096

#if defined(PULSE_DEBUG_HYSTERIA2)
#define HY2_TRACE(...) fprintf(stderr, __VA_ARGS__)
#else
#define HY2_TRACE(...) do { } while (0)
#endif

typedef struct ossl_demo_h3_conn_st OSSL_DEMO_H3_CONN;
typedef struct ossl_demo_h3_stream_st OSSL_DEMO_H3_STREAM;

typedef struct {
    SSL* qconn;
    SSL* stream;
    OSSL_DEMO_H3_CONN* h3;
    BIO_ADDR* peer_addr;
    SSL_CTX* ssl_ctx;
    char status[16];
    int headers_done;
    int stream_done;
    int auth_ok;
    int udp_enabled;
    int recv_error;
    uint64_t rx_value;
    int rx_auto;
} Hy2AuthSession;

typedef struct {
    uint64_t id;
    SSL* s;
    int done_recv_fin;
    void* user_data;
    uint8_t buf[4096];
    size_t buf_cur;
    size_t buf_total;
} OSSL_DEMO_H3_STREAM_IMPL;

struct ossl_demo_h3_conn_st {
    SSL* qconn;
    nghttp3_conn* h3conn;
    void* streams;
    void* user_data;
    int pump_res;
    size_t consumed_app_data;
    nghttp3_recv_data recv_data_cb;
    nghttp3_stream_close stream_close_cb;
    nghttp3_stop_sending stop_sending_cb;
    nghttp3_reset_stream reset_stream_cb;
    nghttp3_deferred_consume deferred_consume_cb;
};

typedef struct {
    SSL_POLL_ITEM* poll_list;
    OSSL_DEMO_H3_STREAM_IMPL** h3_streams;
    OSSL_DEMO_H3_CONN* conn;
    size_t idx;
} Hy2PollList;

static int hy2_on_recv_header(nghttp3_conn* h3conn, int64_t stream_id, int32_t token, nghttp3_rcbuf* name, nghttp3_rcbuf* value, uint8_t flags, void* conn_user_data, void* stream_user_data);
static int hy2_on_end_headers(nghttp3_conn* h3conn, int64_t stream_id, int fin, void* conn_user_data, void* stream_user_data);
static int hy2_on_end_stream(nghttp3_conn* h3conn, int64_t stream_id, void* conn_user_data, void* stream_user_data);

static unsigned long h3_stream_hash(const OSSL_DEMO_H3_STREAM_IMPL* s) {
    return (unsigned long)s->id;
}

static int h3_stream_eq(const OSSL_DEMO_H3_STREAM_IMPL* a, const OSSL_DEMO_H3_STREAM_IMPL* b) {
    if (a->id < b->id) {
        return -1;
    }
    if (a->id > b->id) {
        return 1;
    }
    return 0;
}

DEFINE_LHASH_OF_EX(OSSL_DEMO_H3_STREAM_IMPL);

static void h3_stream_free(OSSL_DEMO_H3_STREAM_IMPL* s) {
    if (s == NULL) {
        return;
    }
    SSL_free(s->s);
    OPENSSL_free(s);
}

static void make_nv(nghttp3_nv* nv, const char* name, const char* value) {
    nv->name = (const uint8_t*)name;
    nv->value = (const uint8_t*)value;
    nv->namelen = strlen(name);
    nv->valuelen = strlen(value);
    nv->flags = NGHTTP3_NV_FLAG_NONE;
}

static void hy2_random_padding(char* out, size_t min_len, size_t max_len) {
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    unsigned int seed = 0;
    size_t i = 0;
    size_t len = min_len;

    if (max_len <= min_len) {
        max_len = min_len + 1;
    }

    if (RAND_bytes((unsigned char*)&seed, sizeof(seed)) != 1) {
        seed = (unsigned int)rand();
    }

    len = min_len + (seed % (unsigned int)(max_len - min_len));
    for (i = 0; i < len; ++i) {
        unsigned char ch = 0;
        if (RAND_bytes(&ch, 1) != 1) {
            ch = (unsigned char)(rand() & 0xff);
        }
        out[i] = alphabet[ch % (sizeof(alphabet) - 1)];
    }
    out[len] = '\0';
}

static void hy2_print_ssl_errors(const char* context) {
    fprintf(stderr, "%s\n", context);

    if (ERR_peek_error() == 0) {
        fprintf(stderr, "(no OpenSSL error details)\n");
        return;
    }
    ERR_print_errors_fp(stderr);
}

static SSL* hy2_get_event_leader(SSL* ssl) {
    SSL* leader = NULL;

    if (ssl == NULL) {
        return NULL;
    }

    if (SSL_is_connection(ssl)) {
        return ssl;
    }

    leader = SSL_get0_connection(ssl);
    return leader != NULL ? leader : ssl;
}

static void hy2_pause_briefly(void) {
#if PLATFORM_IS_WINDOWS
    Sleep(1);
#else
    usleep(1000);
#endif
}

static void hy2_clamp_timeout(struct timeval* tv) {
    if (tv != NULL && tv->tv_sec == 0 && tv->tv_usec == 0) {
        tv->tv_usec = 1000;
    }
}

static void hy2_wait_for_timeout(const struct timeval* tv) {
    if (tv == NULL) {
        hy2_pause_briefly();
        return;
    }

#if PLATFORM_IS_WINDOWS
    {
        DWORD wait_ms = (DWORD)(tv->tv_sec * 1000);
        wait_ms += (DWORD)((tv->tv_usec + 999) / 1000);
        Sleep(wait_ms > 0 ? wait_ms : 1);
    }
#else
    {
        useconds_t wait_us = (useconds_t)(tv->tv_sec * 1000000L);
        wait_us += (useconds_t)tv->tv_usec;
        usleep(wait_us > 0 ? wait_us : 1000);
    }
#endif
}

static int create_socket_bio(const char* host, int port, BIO** out_bio, BIO_ADDR** out_peer_addr) {
    char port_string[16];
    int sock = -1;
    BIO* bio = NULL;

    snprintf(port_string, sizeof(port_string), "%d", port);

#if defined(__ANDROID__)
    struct addrinfo hints;
    struct addrinfo* res = NULL;
    struct addrinfo* ai = NULL;
    int gai_result = 0;
    int last_error = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    gai_result = getaddrinfo(host, port_string, &hints, &res);
    if (gai_result != 0 || res == NULL) {
        fprintf(stderr, "Hysteria2 UDP getaddrinfo failed for %s:%s, family=%d, code=%d, errno=%d\n",
            host, port_string, AF_UNSPEC, gai_result, WSAGetLastError());
        return -1;
    }

    for (ai = res; ai != NULL; ai = ai->ai_next) {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock == -1) {
            last_error = WSAGetLastError();
            fprintf(stderr, "Hysteria2 UDP socket() failed for %s:%s, family=%d, errno=%d\n",
                host, port_string, ai->ai_family, last_error);
            continue;
        }

        if (connect(sock, ai->ai_addr, (socklen_t)ai->ai_addrlen) != 0) {
            last_error = WSAGetLastError();
            fprintf(stderr, "Hysteria2 UDP connect() failed for %s:%s, family=%d, errno=%d\n",
                host, port_string, ai->ai_family, last_error);
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }

        if (!BIO_socket_nbio(sock, 1)) {
            last_error = WSAGetLastError();
            fprintf(stderr, "Hysteria2 UDP nonblocking setup failed for %s:%s, errno=%d\n",
                host, port_string, last_error);
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }

        *out_peer_addr = BIO_ADDR_new();
        if (*out_peer_addr == NULL ||
            (ai->ai_family == AF_INET && !BIO_ADDR_rawmake(
                *out_peer_addr,
                AF_INET,
                &((struct sockaddr_in*)ai->ai_addr)->sin_addr,
                sizeof(struct in_addr),
                ntohs(((struct sockaddr_in*)ai->ai_addr)->sin_port))) ||
            (ai->ai_family == AF_INET6 && !BIO_ADDR_rawmake(
                *out_peer_addr,
                AF_INET6,
                &((struct sockaddr_in6*)ai->ai_addr)->sin6_addr,
                sizeof(struct in6_addr),
                ntohs(((struct sockaddr_in6*)ai->ai_addr)->sin6_port)))) {
            fprintf(stderr, "Hysteria2 UDP peer address build failed for %s:%s\n", host, port_string);
            if (*out_peer_addr != NULL) {
                BIO_ADDR_free(*out_peer_addr);
                *out_peer_addr = NULL;
            }
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }

        bio = BIO_new(BIO_s_datagram());
        if (bio == NULL) {
            hy2_print_ssl_errors("Hysteria2 failed to create datagram BIO.");
            BIO_ADDR_free(*out_peer_addr);
            *out_peer_addr = NULL;
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }

        BIO_set_fd(bio, sock, BIO_CLOSE);
        *out_bio = bio;
        freeaddrinfo(res);
        return 0;
    }

    freeaddrinfo(res);
    return -1;
#else
    BIO_ADDRINFO* res = NULL;
    const BIO_ADDRINFO* ai = NULL;

    if (!BIO_lookup_ex(host, port_string, BIO_LOOKUP_CLIENT, AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, &res)) {
        return -1;
    }

    for (ai = res; ai != NULL; ai = BIO_ADDRINFO_next(ai)) {
        sock = BIO_socket(BIO_ADDRINFO_family(ai), SOCK_DGRAM, 0, 0);
        if (sock == -1) {
            continue;
        }

        if (!BIO_connect(sock, BIO_ADDRINFO_address(ai), 0)) {
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }

        if (!BIO_socket_nbio(sock, 1)) {
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }

        *out_peer_addr = BIO_ADDR_dup(BIO_ADDRINFO_address(ai));
        if (*out_peer_addr == NULL) {
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }

        bio = BIO_new(BIO_s_datagram());
        if (bio == NULL) {
            BIO_ADDR_free(*out_peer_addr);
            *out_peer_addr = NULL;
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }

        BIO_set_fd(bio, sock, BIO_CLOSE);
        *out_bio = bio;
        BIO_ADDRINFO_free(res);
        return 0;
    }

    BIO_ADDRINFO_free(res);
    return -1;
#endif
}

static int quic_wait_for_activity(SSL* ssl) {
    fd_set wfds;
    fd_set rfds;
    SSL* leader = hy2_get_event_leader(ssl);
    int sock = SSL_get_fd(leader);
    struct timeval tv;
    struct timeval* tvp = NULL;
    int is_infinite = 0;
    int want_read = 0;
    int want_write = 0;
    int select_result = 0;

    if (sock == -1) {
        return -1;
    }

    FD_ZERO(&wfds);
    FD_ZERO(&rfds);

    want_write = SSL_net_write_desired(leader) ? 1 : 0;
    want_read = SSL_net_read_desired(leader) ? 1 : 0;

    if (want_write) {
        FD_SET(sock, &wfds);
    }
    if (want_read) {
        FD_SET(sock, &rfds);
    }

    if (SSL_get_event_timeout(leader, &tv, &is_infinite) && !is_infinite) {
        hy2_clamp_timeout(&tv);
        tvp = &tv;
    }

    if (!want_read && !want_write) {
        hy2_wait_for_timeout(tvp);
        return SSL_handle_events(leader) == 1 ? 0 : -1;
    }

    select_result = select(sock + 1, &rfds, &wfds, NULL, tvp);
    if (select_result == SOCKET_ERROR) {
        return -1;
    }

    return SSL_handle_events(leader) == 1 ? 0 : -1;
}

static int quic_handle_io_failure(SSL* ssl, int res) {
    switch (SSL_get_error(ssl, res)) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            return quic_wait_for_activity(ssl) == 0 ? 1 : -1;
        case SSL_ERROR_ZERO_RETURN:
            return 0;
        default:
            return -1;
    }
}

static int quic_do_handshake(SSL* ssl) {
    int ret = 0;

    while ((ret = SSL_connect(ssl)) != 1) {
        if (quic_handle_io_failure(ssl, ret) == 1) {
            continue;
        }
        return -1;
    }

    return 0;
}

static OSSL_DEMO_H3_STREAM_IMPL* h3_conn_create_stream(OSSL_DEMO_H3_CONN* conn, int uni) {
    OSSL_DEMO_H3_STREAM_IMPL* s = OPENSSL_zalloc(sizeof(*s));
    uint64_t flags = SSL_STREAM_FLAG_ADVANCE;

    if (s == NULL) {
        return NULL;
    }

    if (uni) {
        flags |= SSL_STREAM_FLAG_UNI;
    }

    s->s = SSL_new_stream(conn->qconn, flags);
    if (s->s == NULL) {
        OPENSSL_free(s);
        return NULL;
    }
    if (!SSL_set_blocking_mode(s->s, 0)) {
        SSL_free(s->s);
        OPENSSL_free(s);
        return NULL;
    }

    s->id = SSL_get_stream_id(s->s);
    lh_OSSL_DEMO_H3_STREAM_IMPL_insert((LHASH_OF(OSSL_DEMO_H3_STREAM_IMPL)*)conn->streams, s);
    return s;
}

static void h3_conn_remove_stream(OSSL_DEMO_H3_CONN* conn, OSSL_DEMO_H3_STREAM_IMPL* s) {
    if (s == NULL) {
        return;
    }
    lh_OSSL_DEMO_H3_STREAM_IMPL_delete((LHASH_OF(OSSL_DEMO_H3_STREAM_IMPL)*)conn->streams, s);
    h3_stream_free(s);
}

static int h3_conn_recv_data(nghttp3_conn* h3conn, int64_t stream_id, const uint8_t* data, size_t datalen, void* conn_user_data, void* stream_user_data) {
    OSSL_DEMO_H3_CONN* conn = (OSSL_DEMO_H3_CONN*)conn_user_data;
    conn->consumed_app_data += datalen;
    if (conn->recv_data_cb != NULL) {
        return conn->recv_data_cb(h3conn, stream_id, data, datalen, conn->user_data, stream_user_data);
    }
    return 0;
}

static int h3_conn_recv_header(nghttp3_conn* h3conn, int64_t stream_id, int32_t token, nghttp3_rcbuf* name, nghttp3_rcbuf* value, uint8_t flags, void* conn_user_data, void* stream_user_data) {
    OSSL_DEMO_H3_CONN* conn = (OSSL_DEMO_H3_CONN*)conn_user_data;
    if (conn->user_data == NULL) {
        return 0;
    }
    return hy2_on_recv_header(h3conn, stream_id, token, name, value, flags, conn->user_data, stream_user_data);
}

static int h3_conn_end_headers(nghttp3_conn* h3conn, int64_t stream_id, int fin, void* conn_user_data, void* stream_user_data) {
    OSSL_DEMO_H3_CONN* conn = (OSSL_DEMO_H3_CONN*)conn_user_data;
    if (conn->user_data == NULL) {
        return 0;
    }
    return hy2_on_end_headers(h3conn, stream_id, fin, conn->user_data, stream_user_data);
}

static int h3_conn_end_stream(nghttp3_conn* h3conn, int64_t stream_id, void* conn_user_data, void* stream_user_data) {
    OSSL_DEMO_H3_CONN* conn = (OSSL_DEMO_H3_CONN*)conn_user_data;
    if (conn->user_data == NULL) {
        return 0;
    }
    return hy2_on_end_stream(h3conn, stream_id, conn->user_data, stream_user_data);
}

static int h3_conn_stream_close(nghttp3_conn* h3conn, int64_t stream_id, uint64_t app_error_code, void* conn_user_data, void* stream_user_data) {
    OSSL_DEMO_H3_CONN* conn = (OSSL_DEMO_H3_CONN*)conn_user_data;
    OSSL_DEMO_H3_STREAM_IMPL* stream = (OSSL_DEMO_H3_STREAM_IMPL*)stream_user_data;
    int ret = 0;

    if (conn->stream_close_cb != NULL) {
        ret = conn->stream_close_cb(h3conn, stream_id, app_error_code, conn->user_data, stream_user_data);
    }

    h3_conn_remove_stream(conn, stream);
    return ret;
}

static int h3_conn_stop_sending(nghttp3_conn* h3conn, int64_t stream_id, uint64_t app_error_code, void* conn_user_data, void* stream_user_data) {
    OSSL_DEMO_H3_CONN* conn = (OSSL_DEMO_H3_CONN*)conn_user_data;
    OSSL_DEMO_H3_STREAM_IMPL* stream = (OSSL_DEMO_H3_STREAM_IMPL*)stream_user_data;
    int ret = 0;

    if (conn->stop_sending_cb != NULL) {
        ret = conn->stop_sending_cb(h3conn, stream_id, app_error_code, conn->user_data, stream_user_data);
    }

    SSL_free(stream->s);
    stream->s = NULL;
    return ret;
}

static int h3_conn_reset_stream(nghttp3_conn* h3conn, int64_t stream_id, uint64_t app_error_code, void* conn_user_data, void* stream_user_data) {
    OSSL_DEMO_H3_CONN* conn = (OSSL_DEMO_H3_CONN*)conn_user_data;
    OSSL_DEMO_H3_STREAM_IMPL* stream = (OSSL_DEMO_H3_STREAM_IMPL*)stream_user_data;
    SSL_STREAM_RESET_ARGS args = { 0 };
    int ret = 0;

    if (conn->reset_stream_cb != NULL) {
        ret = conn->reset_stream_cb(h3conn, stream_id, app_error_code, conn->user_data, stream_user_data);
    }

    if (stream->s != NULL) {
        args.quic_error_code = app_error_code;
        if (!SSL_stream_reset(stream->s, &args, sizeof(args))) {
            return 1;
        }
    }

    return ret;
}

static int h3_conn_deferred_consume(nghttp3_conn* h3conn, int64_t stream_id, size_t consumed, void* conn_user_data, void* stream_user_data) {
    OSSL_DEMO_H3_CONN* conn = (OSSL_DEMO_H3_CONN*)conn_user_data;
    int ret = 0;

    if (conn->deferred_consume_cb != NULL) {
        ret = conn->deferred_consume_cb(h3conn, stream_id, consumed, conn->user_data, stream_user_data);
    }

    conn->consumed_app_data += consumed;
    return ret;
}

static OSSL_DEMO_H3_CONN* h3_conn_new(SSL* qconn, const nghttp3_callbacks* callbacks, void* user_data) {
    OSSL_DEMO_H3_CONN* conn = NULL;
    OSSL_DEMO_H3_STREAM_IMPL* ctl = NULL;
    OSSL_DEMO_H3_STREAM_IMPL* enc = NULL;
    OSSL_DEMO_H3_STREAM_IMPL* dec = NULL;
    nghttp3_callbacks intl_callbacks = { 0 };
    nghttp3_settings settings = { 0 };
    int ec = 0;

    conn = OPENSSL_zalloc(sizeof(*conn));
    if (conn == NULL) {
        return NULL;
    }

    conn->qconn = qconn;
    conn->user_data = user_data;
    conn->streams = lh_OSSL_DEMO_H3_STREAM_IMPL_new(h3_stream_hash, h3_stream_eq);
    if (conn->streams == NULL) {
        OPENSSL_free(conn);
        return NULL;
    }

    ctl = h3_conn_create_stream(conn, 1);
    enc = h3_conn_create_stream(conn, 1);
    dec = h3_conn_create_stream(conn, 1);
    if (ctl == NULL || enc == NULL || dec == NULL) {
        goto err;
    }

    nghttp3_settings_default(&settings);
    if (callbacks != NULL) {
        intl_callbacks = *callbacks;
    }

    conn->recv_data_cb = intl_callbacks.recv_data;
    conn->stream_close_cb = intl_callbacks.stream_close;
    conn->stop_sending_cb = intl_callbacks.stop_sending;
    conn->reset_stream_cb = intl_callbacks.reset_stream;
    conn->deferred_consume_cb = intl_callbacks.deferred_consume;

    intl_callbacks.recv_header = h3_conn_recv_header;
    intl_callbacks.end_headers = h3_conn_end_headers;
    intl_callbacks.end_stream = h3_conn_end_stream;
    intl_callbacks.recv_data = h3_conn_recv_data;
    intl_callbacks.stream_close = h3_conn_stream_close;
    intl_callbacks.stop_sending = h3_conn_stop_sending;
    intl_callbacks.reset_stream = h3_conn_reset_stream;
    intl_callbacks.deferred_consume = h3_conn_deferred_consume;

    ec = nghttp3_conn_client_new(&conn->h3conn, &intl_callbacks, &settings, NULL, conn);
    if (ec < 0) {
        goto err;
    }

    ec = nghttp3_conn_bind_control_stream(conn->h3conn, ctl->id);
    if (ec < 0) {
        goto err;
    }

    ec = nghttp3_conn_bind_qpack_streams(conn->h3conn, enc->id, dec->id);
    if (ec < 0) {
        goto err;
    }

    return conn;

err:
    if (conn->h3conn != NULL) {
        nghttp3_conn_del(conn->h3conn);
    }
    h3_stream_free(ctl);
    h3_stream_free(enc);
    h3_stream_free(dec);
    lh_OSSL_DEMO_H3_STREAM_IMPL_free((LHASH_OF(OSSL_DEMO_H3_STREAM_IMPL)*)conn->streams);
    OPENSSL_free(conn);
    return NULL;
}

static void h3_conn_collect_streams(OSSL_DEMO_H3_STREAM_IMPL* s, void* list_) {
    Hy2PollList* list = (Hy2PollList*)list_;
    list->poll_list[list->idx].desc = SSL_as_poll_descriptor(s->s);
    list->poll_list[list->idx].events = SSL_POLL_EVENT_R;
    list->poll_list[list->idx].revents = 0;
    list->h3_streams[list->idx] = s;
    list->idx += 1;
}

static void h3_conn_pump_stream(OSSL_DEMO_H3_STREAM_IMPL* s, void* conn_) {
    OSSL_DEMO_H3_CONN* conn = (OSSL_DEMO_H3_CONN*)conn_;

    if (!conn->pump_res) {
        return;
    }

    for (;;) {
        int ec = 0;
        size_t num_bytes = 0;
        size_t consumed = 0;
        uint64_t aec = 0;

        if (s->s == NULL || SSL_get_stream_read_state(s->s) == SSL_STREAM_STATE_WRONG_DIR || s->done_recv_fin) {
            break;
        }

        if (s->buf_cur == s->buf_total) {
            ec = SSL_read_ex(s->s, s->buf, sizeof(s->buf), &num_bytes);
            if (ec <= 0) {
                int ssl_error = SSL_get_error(s->s, ec);
                num_bytes = 0;
                if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                    break;
                }
                if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                    HY2_TRACE("Hysteria2 passing FIN to nghttp3 on stream %llu\n",
                        (unsigned long long)s->id);
                    ec = nghttp3_conn_read_stream(conn->h3conn, s->id, NULL, 0, 1);
                    if (ec < 0) {
                        fprintf(stderr, "Hysteria2 nghttp3 failed to process FIN on stream %llu: %s (%d)\n",
                            (unsigned long long)s->id, nghttp3_strerror(ec), ec);
                        goto err;
                    }
                    s->done_recv_fin = 1;
                    if (conn->user_data != NULL && ((Hy2AuthSession*)conn->user_data)->headers_done) {
                        break;
                    }
                } else if (SSL_get_stream_read_state(s->s) == SSL_STREAM_STATE_RESET_REMOTE) {
                    if (!SSL_get_stream_read_error_code(s->s, &aec)) {
                        fprintf(stderr, "Hysteria2 failed to get remote reset code on stream %llu\n",
                            (unsigned long long)s->id);
                        goto err;
                    }
                    ec = nghttp3_conn_close_stream(conn->h3conn, s->id, aec);
                    if (ec < 0) {
                        fprintf(stderr, "Hysteria2 nghttp3 failed to close reset stream %llu: %s (%d)\n",
                            (unsigned long long)s->id, nghttp3_strerror(ec), ec);
                        goto err;
                    }
                    s->done_recv_fin = 1;
                } else {
                    fprintf(stderr, "Hysteria2 SSL_read_ex failed on HTTP/3 stream %llu with error code %d\n",
                        (unsigned long long)s->id, ssl_error);
                    goto err;
                }
            }

            s->buf_cur = 0;
            s->buf_total = num_bytes;
        }

        if (s->buf_cur == s->buf_total) {
            break;
        }

        conn->consumed_app_data = 0;
        HY2_TRACE("Hysteria2 feeding %zu bytes into nghttp3 on stream %llu\n",
            s->buf_total - s->buf_cur, (unsigned long long)s->id);
        ec = nghttp3_conn_read_stream(conn->h3conn, s->id, s->buf + s->buf_cur, s->buf_total - s->buf_cur, 0);
        if (ec < 0) {
            fprintf(stderr, "Hysteria2 nghttp3 failed to read stream %llu: %s (%d)\n",
                (unsigned long long)s->id, nghttp3_strerror(ec), ec);
            goto err;
        }

        consumed = (size_t)ec + conn->consumed_app_data;
        HY2_TRACE("Hysteria2 nghttp3 consumed %zu bytes on stream %llu (protocol=%d, data=%zu)\n",
            consumed, (unsigned long long)s->id, ec, conn->consumed_app_data);
        if (consumed > s->buf_total - s->buf_cur) {
            HY2_TRACE("Hysteria2 clamped consumed bytes on stream %llu from %zu to %zu\n",
                (unsigned long long)s->id, consumed, s->buf_total - s->buf_cur);
            consumed = s->buf_total - s->buf_cur;
        }
        if (consumed == 0) {
            fprintf(stderr, "Hysteria2 nghttp3 made no progress while reading stream %llu\n",
                (unsigned long long)s->id);
            goto err;
        }
        s->buf_cur += consumed;
        conn->consumed_app_data = 0;
        if (conn->user_data != NULL && ((Hy2AuthSession*)conn->user_data)->headers_done) {
            break;
        }
    }

    return;

err:
    conn->pump_res = 0;
}

static int h3_conn_handle_events(OSSL_DEMO_H3_CONN* conn) {
    nghttp3_vec vecs[8] = { 0 };
    int64_t stream_id = 0;
    uint64_t flags = 0;
    int fin = 0;
    int ec = 0;
    size_t poll_num = 0;
    size_t i = 0;
    size_t result_count = 0;
    struct timeval timeout;
    OSSL_DEMO_H3_STREAM_IMPL key;
    OSSL_DEMO_H3_STREAM_IMPL* s = NULL;
    SSL* accepted = NULL;
    Hy2PollList pollist;

    if (conn == NULL) {
        return 0;
    }

    while ((accepted = SSL_accept_stream(conn->qconn, SSL_ACCEPT_STREAM_NO_BLOCK)) != NULL) {
        OSSL_DEMO_H3_STREAM_IMPL* wrapped = OPENSSL_zalloc(sizeof(*wrapped));
        if (wrapped == NULL) {
            fprintf(stderr, "Hysteria2 failed to allocate accepted HTTP/3 stream wrapper.\n");
            return 0;
        }
        wrapped->s = accepted;
        if (!SSL_set_blocking_mode(wrapped->s, 0)) {
            fprintf(stderr, "Hysteria2 failed to switch accepted HTTP/3 stream to non-blocking mode.\n");
            SSL_free(wrapped->s);
            OPENSSL_free(wrapped);
            return 0;
        }
        wrapped->id = SSL_get_stream_id(accepted);
        lh_OSSL_DEMO_H3_STREAM_IMPL_insert((LHASH_OF(OSSL_DEMO_H3_STREAM_IMPL)*)conn->streams, wrapped);
    }

    for (;;) {
        size_t num_vecs = 0;
        size_t total_len = 0;
        size_t total_written = 0;
        size_t last_nonempty = 0;
        int have_nonempty = 0;

        ec = nghttp3_conn_writev_stream(conn->h3conn, &stream_id, &fin, vecs, sizeof(vecs) / sizeof(vecs[0]));
        if (ec < 0) {
            fprintf(stderr, "Hysteria2 nghttp3 failed to produce HTTP/3 output: %s (%d)\n",
                nghttp3_strerror(ec), ec);
            return 0;
        }
        if (ec == 0) {
            break;
        }

        key.id = (uint64_t)stream_id;
        s = lh_OSSL_DEMO_H3_STREAM_IMPL_retrieve((LHASH_OF(OSSL_DEMO_H3_STREAM_IMPL)*)conn->streams, &key);
        if (s == NULL) {
            fprintf(stderr, "Hysteria2 missing HTTP/3 stream object for stream id %lld\n",
                (long long)stream_id);
            return 0;
        }

        num_vecs = (size_t)ec;
        for (i = 0; i < num_vecs; ++i) {
            if (vecs[i].len == 0) {
                continue;
            }
            total_len += vecs[i].len;
            last_nonempty = i;
            have_nonempty = 1;
        }

        for (i = 0; i < num_vecs; ++i) {
            size_t written = 0;

            if (vecs[i].len == 0) {
                continue;
            }

            flags = (fin != 0 && have_nonempty && i == last_nonempty) ? SSL_WRITE_FLAG_CONCLUDE : 0;

            if (s->s == NULL) {
                written = vecs[i].len;
            } else if (!SSL_write_ex2(s->s, vecs[i].base, vecs[i].len, flags, &written)) {
                if (SSL_get_error(s->s, 0) == SSL_ERROR_WANT_WRITE) {
                    nghttp3_conn_block_stream(conn->h3conn, stream_id);
                    written = 0;
                } else {
                    fprintf(stderr, "Hysteria2 failed to write HTTP/3 data to stream %lld with SSL error %d\n",
                        (long long)stream_id, SSL_get_error(s->s, 0));
                    hy2_print_ssl_errors("OpenSSL reported an error while writing HTTP/3 data.");
                    return 0;
                }
            } else {
                nghttp3_conn_unblock_stream(conn->h3conn, stream_id);
            }

            total_written += written;
            if (written > 0) {
                ec = nghttp3_conn_add_write_offset(conn->h3conn, stream_id, written);
                if (ec < 0) {
                    fprintf(stderr, "Hysteria2 nghttp3 failed to advance write offset on stream %lld: %s (%d)\n",
                        (long long)stream_id, nghttp3_strerror(ec), ec);
                    return 0;
                }
                ec = nghttp3_conn_add_ack_offset(conn->h3conn, stream_id, written);
                if (ec < 0) {
                    fprintf(stderr, "Hysteria2 nghttp3 failed to ack write offset on stream %lld: %s (%d)\n",
                        (long long)stream_id, nghttp3_strerror(ec), ec);
                    return 0;
                }
            }
        }

        if (fin && total_written == total_len && total_len == 0) {
            ec = nghttp3_conn_add_write_offset(conn->h3conn, stream_id, 0);
            if (ec < 0) {
                fprintf(stderr, "Hysteria2 nghttp3 failed to finish empty stream %lld: %s (%d)\n",
                    (long long)stream_id, nghttp3_strerror(ec), ec);
                return 0;
            }
        }
    }

    conn->pump_res = 1;
    poll_num = lh_OSSL_DEMO_H3_STREAM_IMPL_num_items((LHASH_OF(OSSL_DEMO_H3_STREAM_IMPL)*)conn->streams);
    if (poll_num == 0) {
        return 1;
    }

    pollist.poll_list = OPENSSL_malloc(sizeof(SSL_POLL_ITEM) * poll_num);
    pollist.h3_streams = OPENSSL_malloc(sizeof(OSSL_DEMO_H3_STREAM_IMPL*) * poll_num);
    if (pollist.poll_list == NULL || pollist.h3_streams == NULL) {
        fprintf(stderr, "Hysteria2 failed to allocate HTTP/3 poll list.\n");
        OPENSSL_free(pollist.poll_list);
        OPENSSL_free(pollist.h3_streams);
        return 0;
    }
    pollist.conn = conn;
    pollist.idx = 0;

    lh_OSSL_DEMO_H3_STREAM_IMPL_doall_arg((LHASH_OF(OSSL_DEMO_H3_STREAM_IMPL)*)conn->streams, h3_conn_collect_streams, &pollist);

    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    result_count = 0;

    if (!SSL_poll(pollist.poll_list, pollist.idx, sizeof(SSL_POLL_ITEM), &timeout, 0, &result_count)) {
        hy2_print_ssl_errors("Hysteria2 SSL_poll failed while handling HTTP/3 events.");
        OPENSSL_free(pollist.poll_list);
        OPENSSL_free(pollist.h3_streams);
        return 0;
    }

    for (i = 0; result_count != 0 && i < pollist.idx; ++i) {
        if (pollist.poll_list[i].revents == SSL_POLL_EVENT_R) {
            result_count -= 1;
            h3_conn_pump_stream(pollist.h3_streams[i], conn);
            if (conn->user_data != NULL && ((Hy2AuthSession*)conn->user_data)->headers_done) {
                OPENSSL_free(pollist.poll_list);
                OPENSSL_free(pollist.h3_streams);
                return conn->pump_res ? 1 : 0;
            }
        }
    }

    OPENSSL_free(pollist.poll_list);
    OPENSSL_free(pollist.h3_streams);
    return conn->pump_res ? 1 : 0;
}

static void h3_conn_free(OSSL_DEMO_H3_CONN* conn) {
    if (conn == NULL) {
        return;
    }
    lh_OSSL_DEMO_H3_STREAM_IMPL_doall((LHASH_OF(OSSL_DEMO_H3_STREAM_IMPL)*)conn->streams, (void (*)(OSSL_DEMO_H3_STREAM_IMPL*))h3_stream_free);
    nghttp3_conn_del(conn->h3conn);
    lh_OSSL_DEMO_H3_STREAM_IMPL_free((LHASH_OF(OSSL_DEMO_H3_STREAM_IMPL)*)conn->streams);
    OPENSSL_free(conn);
}

static int hy2_on_recv_header(nghttp3_conn* h3conn, int64_t stream_id, int32_t token, nghttp3_rcbuf* name, nghttp3_rcbuf* value, uint8_t flags, void* conn_user_data, void* stream_user_data) {
    Hy2AuthSession* session = (Hy2AuthSession*)conn_user_data;
    nghttp3_vec vname = nghttp3_rcbuf_get_buf(name);
    nghttp3_vec vvalue = nghttp3_rcbuf_get_buf(value);
    char name_buf[128];
    char value_buf[256];
    size_t name_len = vname.len >= sizeof(name_buf) ? sizeof(name_buf) - 1 : vname.len;
    size_t value_len = vvalue.len >= sizeof(value_buf) ? sizeof(value_buf) - 1 : vvalue.len;

    (void)h3conn;
    (void)stream_id;
    (void)token;
    (void)flags;
    (void)stream_user_data;

    memcpy(name_buf, vname.base, name_len);
    name_buf[name_len] = '\0';
    memcpy(value_buf, vvalue.base, value_len);
    value_buf[value_len] = '\0';
    HY2_TRACE("Hysteria2 auth header on stream %lld: %s = %s\n",
        (long long)stream_id, name_buf, value_buf);

    if (strcmp(name_buf, ":status") == 0) {
        strncpy(session->status, value_buf, sizeof(session->status) - 1);
        session->status[sizeof(session->status) - 1] = '\0';
    } else if (_stricmp(name_buf, "Hysteria-UDP") == 0) {
        session->udp_enabled = _stricmp(value_buf, "true") == 0 ? 1 : 0;
    } else if (_stricmp(name_buf, "Hysteria-CC-RX") == 0) {
        if (_stricmp(value_buf, "auto") == 0) {
            session->rx_auto = 1;
        } else {
            session->rx_value = strtoull(value_buf, NULL, 10);
        }
    }

    return 0;
}

static int hy2_on_end_headers(nghttp3_conn* h3conn, int64_t stream_id, int fin, void* conn_user_data, void* stream_user_data) {
    Hy2AuthSession* session = (Hy2AuthSession*)conn_user_data;

    (void)h3conn;
    (void)stream_id;
    (void)fin;
    (void)stream_user_data;

    session->headers_done = 1;
    session->auth_ok = atoi(session->status) == HY2_STATUS_AUTH_OK;
    HY2_TRACE("Hysteria2 auth headers complete on stream %lld, status=%s, fin=%d\n",
        (long long)stream_id, session->status[0] != '\0' ? session->status : "(missing)", fin);
    if (fin) {
        session->stream_done = 1;
    }
    return 0;
}

static int hy2_on_end_stream(nghttp3_conn* h3conn, int64_t stream_id, void* conn_user_data, void* stream_user_data) {
    Hy2AuthSession* session = (Hy2AuthSession*)conn_user_data;

    (void)h3conn;
    (void)stream_id;
    (void)stream_user_data;

    session->stream_done = 1;
    return 0;
}

static int hy2_on_recv_data(nghttp3_conn* h3conn, int64_t stream_id, const uint8_t* data, size_t datalen, void* conn_user_data, void* stream_user_data) {
    Hy2AuthSession* session = (Hy2AuthSession*)conn_user_data;

    (void)h3conn;
    (void)stream_id;
    (void)data;
    (void)stream_user_data;

    if (datalen > 0) {
        HY2_TRACE("Hysteria2 auth response carried %zu bytes of DATA on stream %lld\n",
            datalen, (long long)stream_id);
        session->recv_error = 1;
    }
    return 0;
}

static int hy2_h3_submit_request(OSSL_DEMO_H3_CONN* conn, const nghttp3_nv* nva, size_t nvlen, const nghttp3_data_reader* dr, void* user_data) {
    OSSL_DEMO_H3_STREAM_IMPL* stream = h3_conn_create_stream(conn, 0);
    int ec = 0;

    if (stream == NULL) {
        return 0;
    }

    stream->user_data = user_data;
    ec = nghttp3_conn_submit_request(conn->h3conn, (int64_t)stream->id, nva, nvlen, dr, stream);
    if (ec < 0) {
        h3_conn_remove_stream(conn, stream);
        return 0;
    }
    return 1;
}

static int hy2_connect_and_auth(Hy2AuthSession* session, const EndpointConfig* endpoint) {
    BIO* bio = NULL;
    nghttp3_callbacks callbacks = { 0 };
    nghttp3_nv headers[7];
    char authority[] = "hysteria";
    char path[] = "/auth";
    char padding[HY2_AUTH_PADDING_MAX + 1];
    char rx_header[] = "0";
    size_t num_headers = 0;
    static const unsigned char alpn[] = { 2, 'h', '3' };

    memset(session, 0, sizeof(*session));

    session->ssl_ctx = SSL_CTX_new(OSSL_QUIC_client_method());
    if (session->ssl_ctx == NULL) {
        hy2_print_ssl_errors("Hysteria2 failed to create QUIC SSL context.");
        return -1;
    }

    if (endpoint->skip_cert_verify) {
        SSL_CTX_set_verify(session->ssl_ctx, SSL_VERIFY_NONE, NULL);
    } else {
        SSL_CTX_set_verify(session->ssl_ctx, SSL_VERIFY_PEER, NULL);
        if (!SSL_CTX_set_default_verify_paths(session->ssl_ctx)) {
            hy2_print_ssl_errors("Hysteria2 failed to load default CA paths.");
            return -1;
        }
    }

    if (create_socket_bio(endpoint->server, endpoint->port, &bio, &session->peer_addr) != 0) {
        fprintf(stderr, "Hysteria2 failed to create UDP socket for %s:%d\n", endpoint->server, endpoint->port);
        return -1;
    }

    session->qconn = SSL_new(session->ssl_ctx);
    if (session->qconn == NULL) {
        BIO_free_all(bio);
        hy2_print_ssl_errors("Hysteria2 failed to create QUIC connection object.");
        return -1;
    }

    SSL_set_bio(session->qconn, bio, bio);

    if (SSL_set_alpn_protos(session->qconn, alpn, sizeof(alpn)) != 0) {
        hy2_print_ssl_errors("Hysteria2 failed to configure ALPN.");
        return -1;
    }

    if (!SSL_set_default_stream_mode(session->qconn, SSL_DEFAULT_STREAM_MODE_NONE)) {
        hy2_print_ssl_errors("Hysteria2 failed to configure QUIC stream mode.");
        return -1;
    }

    if (!SSL_set_tlsext_host_name(session->qconn, endpoint->hysteria2.sni)) {
        hy2_print_ssl_errors("Hysteria2 failed to configure SNI.");
        return -1;
    }

    if (!endpoint->skip_cert_verify && !SSL_set1_host(session->qconn, endpoint->hysteria2.sni)) {
        hy2_print_ssl_errors("Hysteria2 failed to configure certificate hostname verification.");
        return -1;
    }

    if (!SSL_set1_initial_peer_addr(session->qconn, session->peer_addr)) {
        hy2_print_ssl_errors("Hysteria2 failed to configure QUIC peer address.");
        return -1;
    }

    if (!SSL_set_blocking_mode(session->qconn, 0)) {
        hy2_print_ssl_errors("Hysteria2 failed to switch QUIC connection to non-blocking mode.");
        return -1;
    }

    if (quic_do_handshake(session->qconn) != 0) {
        hy2_print_ssl_errors("Hysteria2 QUIC handshake failed.");
        return -1;
    }

    callbacks.recv_header = hy2_on_recv_header;
    callbacks.end_headers = hy2_on_end_headers;
    callbacks.end_stream = hy2_on_end_stream;
    callbacks.recv_data = hy2_on_recv_data;

    session->h3 = h3_conn_new(session->qconn, &callbacks, session);
    if (session->h3 == NULL) {
        hy2_print_ssl_errors("Hysteria2 failed to initialize HTTP/3 state.");
        return -1;
    }

    hy2_random_padding(padding, HY2_AUTH_PADDING_MIN, HY2_AUTH_PADDING_MAX);

    make_nv(&headers[num_headers++], ":method", "POST");
    make_nv(&headers[num_headers++], ":scheme", "https");
    make_nv(&headers[num_headers++], ":authority", authority);
    make_nv(&headers[num_headers++], ":path", path);
    make_nv(&headers[num_headers++], "hysteria-auth", endpoint->hysteria2.password);
    make_nv(&headers[num_headers++], "hysteria-cc-rx", rx_header);
    make_nv(&headers[num_headers++], "hysteria-padding", padding);

    if (!hy2_h3_submit_request(session->h3, headers, num_headers, NULL, NULL)) {
        hy2_print_ssl_errors("Hysteria2 failed to submit auth request.");
        h3_conn_free(session->h3);
        session->h3 = NULL;
        return -1;
    }

    while (!session->headers_done && !session->recv_error) {
        HY2_TRACE("Hysteria2 auth loop: headers_done=%d auth_ok=%d recv_error=%d\n",
            session->headers_done, session->auth_ok, session->recv_error);
        if (!h3_conn_handle_events(session->h3)) {
            hy2_print_ssl_errors("Hysteria2 HTTP/3 event loop failed during auth.");
            h3_conn_free(session->h3);
            session->h3 = NULL;
            return -1;
        }
        HY2_TRACE("Hysteria2 auth loop after events: headers_done=%d auth_ok=%d recv_error=%d\n",
            session->headers_done, session->auth_ok, session->recv_error);
        if (!session->headers_done && !session->recv_error && quic_wait_for_activity(session->qconn) != 0) {
            hy2_print_ssl_errors("Hysteria2 QUIC event wait failed during auth.");
            h3_conn_free(session->h3);
            session->h3 = NULL;
            return -1;
        }
    }

    if (!session->headers_done || !session->auth_ok || session->recv_error) {
        fprintf(stderr, "Hysteria2 auth failed with status: %s\n", session->status[0] != '\0' ? session->status : "(missing)");
        return -1;
    }

    HY2_TRACE("Hysteria2 auth OK. UDP=%s, CCRX=%s\n",
        session->udp_enabled ? "true" : "false",
        session->rx_auto ? "auto" : "fixed");
    return 0;
}

static size_t hy2_varint_write(uint8_t* out, uint64_t value) {
    if (value <= 63) {
        out[0] = (uint8_t)value;
        return 1;
    }
    if (value <= 16383) {
        out[0] = (uint8_t)((value >> 8) | 0x40);
        out[1] = (uint8_t)value;
        return 2;
    }
    if (value <= 1073741823ULL) {
        out[0] = (uint8_t)((value >> 24) | 0x80);
        out[1] = (uint8_t)(value >> 16);
        out[2] = (uint8_t)(value >> 8);
        out[3] = (uint8_t)value;
        return 4;
    }
    out[0] = (uint8_t)((value >> 56) | 0xC0);
    out[1] = (uint8_t)(value >> 48);
    out[2] = (uint8_t)(value >> 40);
    out[3] = (uint8_t)(value >> 32);
    out[4] = (uint8_t)(value >> 24);
    out[5] = (uint8_t)(value >> 16);
    out[6] = (uint8_t)(value >> 8);
    out[7] = (uint8_t)value;
    return 8;
}

static int hy2_read_exact_stream(SSL* stream, uint8_t* buf, size_t len) {
    size_t total = 0;

    while (total < len) {
        size_t got = 0;
        int ret = SSL_read_ex(stream, buf + total, len - total, &got);
        if (ret == 1) {
            total += got;
            continue;
        }
        if (quic_handle_io_failure(stream, ret) == 1) {
            continue;
        }
        return -1;
    }

    return 0;
}

static int hy2_write_all_stream(SSL* stream, const uint8_t* buf, size_t len, uint64_t flags) {
    size_t total = 0;

    while (total < len) {
        size_t written = 0;
        int ret = SSL_write_ex2(stream, buf + total, len - total, flags, &written);
        if (ret == 1) {
            total += written;
            flags = 0;
            continue;
        }
        if (quic_handle_io_failure(stream, ret) == 1) {
            continue;
        }
        return -1;
    }

    return 0;
}

static int hy2_read_varint(SSL* stream, uint64_t* out) {
    uint8_t first = 0;
    uint8_t buf[8];
    size_t len = 0;
    size_t i = 0;

    if (hy2_read_exact_stream(stream, &first, 1) != 0) {
        return -1;
    }

    buf[0] = first;
    len = (size_t)(1U << ((first & 0xC0) >> 6));
    if (len > 1 && hy2_read_exact_stream(stream, buf + 1, len - 1) != 0) {
        return -1;
    }

    switch (len) {
        case 1:
            *out = buf[0] & 0x3F;
            return 0;
        case 2:
            *out = ((uint64_t)(buf[0] & 0x3F) << 8) | buf[1];
            return 0;
        case 4:
            *out = ((uint64_t)(buf[0] & 0x3F) << 24) | ((uint64_t)buf[1] << 16) | ((uint64_t)buf[2] << 8) | buf[3];
            return 0;
        case 8:
            *out = (uint64_t)(buf[0] & 0x3F) << 56;
            for (i = 1; i < 8; ++i) {
                *out |= (uint64_t)buf[i] << ((7 - i) * 8);
            }
            return 0;
        default:
            return -1;
    }
}

static void hy2_cleanup(Hy2AuthSession* session) {
    if (session->stream != NULL) {
        SSL_free(session->stream);
        session->stream = NULL;
    }
    if (session->h3 != NULL) {
        h3_conn_free(session->h3);
        session->h3 = NULL;
    }
    if (session->qconn != NULL) {
        SSL_shutdown(session->qconn);
        SSL_free(session->qconn);
        session->qconn = NULL;
    }
    if (session->peer_addr != NULL) {
        BIO_ADDR_free(session->peer_addr);
        session->peer_addr = NULL;
    }
    if (session->ssl_ctx != NULL) {
        SSL_CTX_free(session->ssl_ctx);
        session->ssl_ctx = NULL;
    }
}

static int hy2_open_tcp_stream(Hy2AuthSession* session, const Destination* destination) {
    char address[320];
    char padding[HY2_TCP_PADDING_MAX + 1];
    uint8_t request[4096];
    uint8_t status = 0;
    uint64_t msg_len = 0;
    uint64_t padding_len = 0;
    size_t offset = 0;
    size_t address_len = 0;
    char msg[HY2_MAX_RESPONSE_MSG + 1];

    format_destination(destination, address, sizeof(address));
    address_len = strlen(address);
    hy2_random_padding(padding, HY2_TCP_PADDING_MIN, HY2_TCP_PADDING_MAX);
    HY2_TRACE("Hysteria2 opening TCP stream for %s\n", address);

    session->stream = SSL_new_stream(session->qconn, SSL_STREAM_FLAG_ADVANCE);
    if (session->stream == NULL) {
        hy2_print_ssl_errors("Hysteria2 failed to create a TCP stream.");
        return -1;
    }

    if (!SSL_set_blocking_mode(session->stream, 0)) {
        hy2_print_ssl_errors("Hysteria2 failed to switch TCP stream to non-blocking mode.");
        return -1;
    }

    offset += hy2_varint_write(request + offset, HY2_FRAME_TYPE_TCP_REQUEST);
    offset += hy2_varint_write(request + offset, address_len);
    memcpy(request + offset, address, address_len);
    offset += address_len;
    offset += hy2_varint_write(request + offset, strlen(padding));
    memcpy(request + offset, padding, strlen(padding));
    offset += strlen(padding);

    if (hy2_write_all_stream(session->stream, request, offset, 0) != 0) {
        fprintf(stderr, "Hysteria2 failed to send TCP request for %s\n", address);
        hy2_print_ssl_errors("OpenSSL reported an error while sending the Hysteria2 TCP request.");
        return -1;
    }
    HY2_TRACE("Hysteria2 TCP request sent for %s\n", address);

    if (hy2_read_exact_stream(session->stream, &status, 1) != 0) {
        fprintf(stderr, "Hysteria2 failed to read TCP response status for %s\n", address);
        return -1;
    }
    if (hy2_read_varint(session->stream, &msg_len) != 0 || msg_len > HY2_MAX_RESPONSE_MSG) {
        fprintf(stderr, "Hysteria2 returned an invalid TCP response message length for %s\n", address);
        return -1;
    }
    if (msg_len > 0 && hy2_read_exact_stream(session->stream, (uint8_t*)msg, (size_t)msg_len) != 0) {
        fprintf(stderr, "Hysteria2 failed to read TCP response message for %s\n", address);
        return -1;
    }
    msg[msg_len] = '\0';
    if (hy2_read_varint(session->stream, &padding_len) != 0 || padding_len > HY2_MAX_PADDING) {
        fprintf(stderr, "Hysteria2 returned an invalid TCP response padding length for %s\n", address);
        return -1;
    }
    if (padding_len > 0) {
        uint8_t discard[256];
        while (padding_len > 0) {
            size_t chunk = padding_len > sizeof(discard) ? sizeof(discard) : (size_t)padding_len;
            if (hy2_read_exact_stream(session->stream, discard, chunk) != 0) {
                fprintf(stderr, "Hysteria2 failed to read TCP response padding for %s\n", address);
                return -1;
            }
            padding_len -= chunk;
        }
    }

    if (status != 0) {
        fprintf(stderr, "Hysteria2 upstream rejected the request: %s\n", msg);
        return -1;
    }

    return 0;
}

static int hy2_remote_has_pending(SSL* stream) {
    return SSL_pending(stream) > 0 ? 1 : 0;
}

int proxy_hysteria2_client(SOCKET client_socket, const EndpointConfig* endpoint, const ProxySession* proxy_session) {
    Hy2AuthSession session;
    const Destination* destination = &proxy_session->destination;
    uint8_t buffer[4096];
    int relay_error = 0;

    if (hy2_connect_and_auth(&session, endpoint) != 0) {
        fprintf(stderr, "Hysteria2 connect/auth stage failed for %s:%d\n", endpoint->server, endpoint->port);
        if (proxy_session->handshake_type == CLIENT_HANDSHAKE_SOCKS5) {
            send_socks_reply(client_socket, 0x05);
        } else if (proxy_session->handshake_type == CLIENT_HANDSHAKE_HTTP_CONNECT) {
            send_http_connect_reply(client_socket, 502);
        } else {
            send_http_forward_error(client_socket, 502, "Bad Gateway");
        }
        hy2_cleanup(&session);
        return -1;
    }

    if (hy2_open_tcp_stream(&session, destination) != 0) {
        fprintf(stderr, "Hysteria2 TCP open stage failed.\n");
        if (proxy_session->handshake_type == CLIENT_HANDSHAKE_SOCKS5) {
            send_socks_reply(client_socket, 0x05);
        } else if (proxy_session->handshake_type == CLIENT_HANDSHAKE_HTTP_CONNECT) {
            send_http_connect_reply(client_socket, 502);
        } else {
            send_http_forward_error(client_socket, 502, "Bad Gateway");
        }
        hy2_cleanup(&session);
        return -1;
    }

    if (proxy_session->handshake_type == CLIENT_HANDSHAKE_SOCKS5) {
        if (send_socks_reply(client_socket, 0x00) != 0) {
            hy2_cleanup(&session);
            return -1;
        }
    } else if (proxy_session->handshake_type == CLIENT_HANDSHAKE_HTTP_CONNECT) {
        if (send_http_connect_reply(client_socket, 200) != 0) {
            hy2_cleanup(&session);
            return -1;
        }
    } else if (proxy_session->initial_data_len > 0) {
        if (hy2_write_all_stream(session.stream, proxy_session->initial_data, proxy_session->initial_data_len, 0) != 0) {
            hy2_cleanup(&session);
            return -1;
        }
    }

    for (;;) {
        fd_set read_fds;
        fd_set write_fds;
        struct timeval timeout;
        struct timeval* timeout_ptr = NULL;
        int client_ready = 0;
        int remote_ready = 0;
        int network_ready = 0;
        int quic_sock = SSL_get_fd(session.qconn);
        int is_infinite = 0;
        int select_result = 0;

        remote_ready = hy2_remote_has_pending(session.stream);

        if (!remote_ready) {
            FD_ZERO(&read_fds);
            FD_ZERO(&write_fds);
            FD_SET(client_socket, &read_fds);

            if (quic_sock != -1) {
                if (SSL_net_read_desired(session.qconn) || !remote_ready) {
                    FD_SET(quic_sock, &read_fds);
                }
                if (SSL_net_write_desired(session.qconn)) {
                    FD_SET(quic_sock, &write_fds);
                }
                if (SSL_get_event_timeout(session.qconn, &timeout, &is_infinite) && !is_infinite) {
                    hy2_clamp_timeout(&timeout);
                    timeout_ptr = &timeout;
                }
            }

            select_result = select((int)((quic_sock >= 0 && (SOCKET)quic_sock > client_socket) ? (SOCKET)quic_sock : client_socket) + 1,
                &read_fds, &write_fds, NULL, timeout_ptr);
            if (select_result == SOCKET_ERROR) {
                relay_error = 1;
                break;
            }

            client_ready = FD_ISSET(client_socket, &read_fds);
            if (quic_sock != -1) {
                network_ready = FD_ISSET(quic_sock, &read_fds) || FD_ISSET(quic_sock, &write_fds) || select_result == 0;
            }

            if (network_ready) {
                if (SSL_handle_events(session.qconn) != 1) {
                    relay_error = 1;
                    break;
                }
                remote_ready = hy2_remote_has_pending(session.stream);
            }
        }

        if (client_ready) {
            int received = recv(client_socket, (char*)buffer, sizeof(buffer), 0);
            if (received <= 0) {
                break;
            }
            if (hy2_write_all_stream(session.stream, buffer, (size_t)received, 0) != 0) {
                relay_error = 1;
                break;
            }
        }

        if (remote_ready || hy2_remote_has_pending(session.stream)) {
            size_t readbytes = 0;
            int ret = SSL_read_ex(session.stream, buffer, sizeof(buffer), &readbytes);
            if (ret == 1) {
                if (send_all_socket(client_socket, buffer, readbytes) != 0) {
                    relay_error = 1;
                    break;
                }
            } else {
                int io = quic_handle_io_failure(session.stream, ret);
                if (io == 1) {
                    continue;
                }
                if (io < 0) {
                    relay_error = 1;
                }
                break;
            }
        }
    }

    if (session.stream != NULL) {
        SSL_stream_conclude(session.stream, 0);
    }
    hy2_cleanup(&session);
    return relay_error ? -1 : 0;
}

#else

int proxy_hysteria2_client(SOCKET client_socket, const EndpointConfig* endpoint, const ProxySession* proxy_session) {
    char destination_text[320];

    (void)endpoint;

    format_destination(&proxy_session->destination, destination_text, sizeof(destination_text));
    fprintf(stderr,
        "Hysteria2 is not available in this Linux build. "
        "The current Linux toolchain lacks the QUIC-enabled OpenSSL/nghttp3 stack required for %s.\n",
        destination_text);
    if (proxy_session->handshake_type == CLIENT_HANDSHAKE_SOCKS5) {
        send_socks_reply(client_socket, 0x07);
    } else if (proxy_session->handshake_type == CLIENT_HANDSHAKE_HTTP_CONNECT) {
        send_http_connect_reply(client_socket, 502);
    } else {
        send_http_forward_error(client_socket, 502, "Bad Gateway");
    }
    return -1;
}

#endif
