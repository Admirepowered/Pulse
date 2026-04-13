#ifndef PULSE_PROXY_H
#define PULSE_PROXY_H

#include "platform.h"
#include "pulse.h"

int send_all_socket(SOCKET socket_fd, const uint8_t* data, size_t len);
int recv_exact_socket(SOCKET socket_fd, uint8_t* data, size_t len);
void format_destination(const Destination* destination, char* out, size_t out_size);

int send_socks_reply(SOCKET client_socket, uint8_t reply_code);
int send_http_connect_reply(SOCKET client_socket, int status_code);
int send_http_forward_error(SOCKET client_socket, int status_code, const char* reason);

int proxy_vless_client(SOCKET client_socket, const EndpointConfig* endpoint, const ProxySession* session);
int proxy_hysteria2_client(SOCKET client_socket, const EndpointConfig* endpoint, const ProxySession* session);
int proxy_shadowsocks_client(SOCKET client_socket, const EndpointConfig* endpoint, const ProxySession* session);
int proxy_shadowsocksr_client(SOCKET client_socket, const EndpointConfig* endpoint, const ProxySession* session);
int proxy_vmess_client(SOCKET client_socket, const EndpointConfig* endpoint, const ProxySession* session);
int proxy_trojan_client(SOCKET client_socket, const EndpointConfig* endpoint, const ProxySession* session);
int proxy_tuic_client(SOCKET client_socket, const EndpointConfig* endpoint, const ProxySession* session);
int proxy_anytls_client(SOCKET client_socket, const EndpointConfig* endpoint, const ProxySession* session);
int proxy_direct_client(SOCKET client_socket, const ProxySession* session);

int detect_and_handle_inbound(SOCKET client_socket, InboundType configured_type, ProxySession* session);

#endif
