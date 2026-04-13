#include <stdio.h>
#include "core/proxy.h"

static int report_unavailable(SOCKET client_socket, const ProxySession* session, const char* protocol_name) {
    fprintf(stderr, "%s outbound is configured but runtime support is not implemented in this build yet.\n", protocol_name);

    if (session->handshake_type == CLIENT_HANDSHAKE_SOCKS5) {
        send_socks_reply(client_socket, 0x07);
    } else if (session->handshake_type == CLIENT_HANDSHAKE_HTTP_CONNECT) {
        send_http_connect_reply(client_socket, 502);
    } else {
        send_http_forward_error(client_socket, 502, "Bad Gateway");
    }

    return -1;
}

int proxy_shadowsocksr_client(SOCKET client_socket, const EndpointConfig* endpoint, const ProxySession* session) {
    (void)endpoint;
    return report_unavailable(client_socket, session, "ShadowsocksR");
}

int proxy_tuic_client(SOCKET client_socket, const EndpointConfig* endpoint, const ProxySession* session) {
    (void)endpoint;
    return report_unavailable(client_socket, session, "TUIC");
}

int proxy_anytls_client(SOCKET client_socket, const EndpointConfig* endpoint, const ProxySession* session) {
    (void)endpoint;
    return report_unavailable(client_socket, session, "AnyTLS");
}
