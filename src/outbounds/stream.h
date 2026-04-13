#ifndef PULSE_OUTBOUND_STREAM_H
#define PULSE_OUTBOUND_STREAM_H

#include <openssl/ssl.h>
#include "proxy.h"

#define PULSE_IO_BUFFER_SIZE 4096
#define PULSE_HTTP_BUFFER_SIZE 8192

typedef struct {
    SOCKET socket_fd;
    SSL_CTX* ssl_ctx;
    SSL* ssl;
    int use_tls;
    int use_ws;
    uint64_t ws_payload_remaining;
    int ws_payload_masked;
    uint8_t ws_mask[4];
    size_t ws_mask_offset;
} RemoteStream;

SOCKET connect_tcp_socket(const char* host, int port);
int remote_stream_connect(RemoteStream* stream, const char* host, int port);
int remote_stream_enable_tls(RemoteStream* stream, const char* tls_host, int skip_cert_verify);
int remote_stream_start_websocket(RemoteStream* stream, const char* path, const char* host);
int remote_stream_send(RemoteStream* stream, const uint8_t* payload, size_t len);
int remote_stream_recv(RemoteStream* stream, uint8_t* out, size_t len);
int remote_stream_recv_exact(RemoteStream* stream, uint8_t* out, size_t len);
int remote_stream_has_pending_data(const RemoteStream* stream);
void remote_stream_shutdown(RemoteStream* stream);
void remote_stream_close(RemoteStream* stream);

#endif
