#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include "core/proxy.h"
#include "outbounds/stream.h"
#include "outbounds/protocol_helpers.h"

static void sha224_hex_lower(const char* password, char out[57]) {
    unsigned char digest[SHA224_DIGEST_LENGTH];
    static const char hex[] = "0123456789abcdef";
    size_t i = 0;

    SHA224((const unsigned char*)password, strlen(password), digest);
    for (i = 0; i < sizeof(digest); ++i) {
        out[i * 2] = hex[(digest[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    out[56] = '\0';
}

static int open_trojan_stream(RemoteStream* stream, const EndpointConfig* endpoint) {
    const char* tls_host = endpoint->trojan.servername[0] != '\0' ? endpoint->trojan.servername : endpoint->server;
    const char* ws_path = endpoint->trojan.ws.path[0] != '\0' ? endpoint->trojan.ws.path : "/";
    const char* ws_host = endpoint->trojan.ws.host[0] != '\0' ? endpoint->trojan.ws.host : tls_host;

    if (remote_stream_connect(stream, endpoint->server, endpoint->port) != 0) {
        fprintf(stderr, "Failed to connect to Trojan upstream %s:%d\n", endpoint->server, endpoint->port);
        return -1;
    }

    if (endpoint->trojan.tls && remote_stream_enable_tls(stream, tls_host, endpoint->skip_cert_verify) != 0) {
        fprintf(stderr, "Trojan TLS handshake failed.\n");
        remote_stream_close(stream);
        return -1;
    }

    if (_stricmp(endpoint->trojan.network, "ws") == 0 &&
        remote_stream_start_websocket(stream, ws_path, ws_host) != 0) {
        fprintf(stderr, "Trojan WebSocket handshake failed.\n");
        remote_stream_close(stream);
        return -1;
    }

    return 0;
}

int proxy_trojan_client(SOCKET client_socket, const EndpointConfig* endpoint, const ProxySession* session) {
    RemoteStream remote_stream;
    char password_hash[57];
    uint8_t request[1024 + MAX_INITIAL_DATA_LEN];
    size_t request_len = 0;
    size_t addr_len = 0;

    if (open_trojan_stream(&remote_stream, endpoint) != 0) {
        if (session->handshake_type == CLIENT_HANDSHAKE_SOCKS5) {
            send_socks_reply(client_socket, 0x05);
        } else if (session->handshake_type == CLIENT_HANDSHAKE_HTTP_CONNECT) {
            send_http_connect_reply(client_socket, 502);
        } else {
            send_http_forward_error(client_socket, 502, "Bad Gateway");
        }
        return -1;
    }

    sha224_hex_lower(endpoint->trojan.password, password_hash);
    memcpy(request + request_len, password_hash, 56);
    request_len += 56;
    request[request_len++] = '\r';
    request[request_len++] = '\n';

    if (encode_destination_socksaddr(&session->destination, 1, request + request_len, sizeof(request) - request_len, &addr_len) != 0) {
        remote_stream_close(&remote_stream);
        return -1;
    }
    request_len += addr_len;
    request[request_len++] = '\r';
    request[request_len++] = '\n';

    if (session->initial_data_len > 0) {
        if (request_len + session->initial_data_len > sizeof(request)) {
            remote_stream_close(&remote_stream);
            return -1;
        }
        memcpy(request + request_len, session->initial_data, session->initial_data_len);
        request_len += session->initial_data_len;
    }

    if (remote_stream_send(&remote_stream, request, request_len) != 0) {
        remote_stream_close(&remote_stream);
        return -1;
    }

    if (session->handshake_type == CLIENT_HANDSHAKE_SOCKS5) {
        if (send_socks_reply(client_socket, 0x00) != 0) {
            remote_stream_close(&remote_stream);
            return -1;
        }
    } else if (session->handshake_type == CLIENT_HANDSHAKE_HTTP_CONNECT) {
        if (send_http_connect_reply(client_socket, 200) != 0) {
            remote_stream_close(&remote_stream);
            return -1;
        }
    }

    relay_remote_stream_client(client_socket, &remote_stream, session);
    remote_stream_shutdown(&remote_stream);
    remote_stream_close(&remote_stream);
    return 0;
}
