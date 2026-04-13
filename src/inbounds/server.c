#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "core/proxy.h"

typedef struct {
    SOCKET client_socket;
    const Config* config;
} ClientThreadArgs;

static int dispatch_proxy_client(SOCKET client_socket, const EndpointConfig* endpoint, const ProxySession* session) {
    switch (endpoint->type) {
        case ENDPOINT_TYPE_VLESS:
            return proxy_vless_client(client_socket, endpoint, session);
        case ENDPOINT_TYPE_HYSTERIA2:
            return proxy_hysteria2_client(client_socket, endpoint, session);
        case ENDPOINT_TYPE_SHADOWSOCKS:
            return proxy_shadowsocks_client(client_socket, endpoint, session);
        case ENDPOINT_TYPE_SHADOWSOCKSR:
            return proxy_shadowsocksr_client(client_socket, endpoint, session);
        case ENDPOINT_TYPE_VMESS:
            return proxy_vmess_client(client_socket, endpoint, session);
        case ENDPOINT_TYPE_TROJAN:
            return proxy_trojan_client(client_socket, endpoint, session);
        case ENDPOINT_TYPE_TUIC:
            return proxy_tuic_client(client_socket, endpoint, session);
        case ENDPOINT_TYPE_ANYTLS:
            return proxy_anytls_client(client_socket, endpoint, session);
        default:
            if (session->handshake_type == CLIENT_HANDSHAKE_SOCKS5) {
                send_socks_reply(client_socket, 0x07);
            } else if (session->handshake_type == CLIENT_HANDSHAKE_HTTP_CONNECT) {
                send_http_connect_reply(client_socket, 502);
            } else {
                send_http_forward_error(client_socket, 502, "Bad Gateway");
            }
            return -1;
    }
}

static void describe_route(const RouteDecision* decision, char* out, size_t out_size) {
    if (decision->action == ROUTE_ACTION_DIRECT) {
        snprintf(out, out_size, "%s", "direct");
        return;
    }
    if (decision->action == ROUTE_ACTION_REJECT) {
        snprintf(out, out_size, "%s", "reject");
        return;
    }
    if (decision->endpoint != NULL) {
        snprintf(out, out_size, "%s (%s)", decision->endpoint->key, decision->endpoint->name);
        return;
    }

    snprintf(out, out_size, "%s", "unknown");
}

#if PLATFORM_IS_WINDOWS
static unsigned __stdcall client_thread_main(void* arg) {
#else
static void* client_thread_main(void* arg) {
#endif
    ClientThreadArgs* client_args = (ClientThreadArgs*)arg;
    SOCKET client_socket = client_args->client_socket;
    const Config* config = client_args->config;
    RouteDecision decision;
    ProxySession session;
    char destination_text[320];
    char route_text[320];
    int result = -1;

    free(client_args);

    if (detect_and_handle_inbound(client_socket, config->type, &session) != 0) {
        closesocket(client_socket);
#if PLATFORM_IS_WINDOWS
        return 0;
#else
        return NULL;
#endif
    }

    if (resolve_route(config, &session.destination, &decision) != 0) {
        if (session.handshake_type == CLIENT_HANDSHAKE_SOCKS5) {
            send_socks_reply(client_socket, 0x01);
        } else if (session.handshake_type == CLIENT_HANDSHAKE_HTTP_CONNECT) {
            send_http_connect_reply(client_socket, 502);
        } else {
            send_http_forward_error(client_socket, 502, "Bad Gateway");
        }
        closesocket(client_socket);
#if PLATFORM_IS_WINDOWS
        return 0;
#else
        return NULL;
#endif
    }

    format_destination(&session.destination, destination_text, sizeof(destination_text));
    describe_route(&decision, route_text, sizeof(route_text));
    printf("Connecting %s via %s\n", destination_text, route_text);
    if (decision.rule != NULL) {
        printf("Matched rule: %s\n", decision.rule->name);
    }
    fflush(stdout);

    switch (decision.action) {
        case ROUTE_ACTION_PROXY:
            if (decision.endpoint == NULL) {
                if (session.handshake_type == CLIENT_HANDSHAKE_SOCKS5) {
                    send_socks_reply(client_socket, 0x01);
                } else if (session.handshake_type == CLIENT_HANDSHAKE_HTTP_CONNECT) {
                    send_http_connect_reply(client_socket, 502);
                } else {
                    send_http_forward_error(client_socket, 502, "Bad Gateway");
                }
                break;
            }
            result = dispatch_proxy_client(client_socket, decision.endpoint, &session);
            break;
        case ROUTE_ACTION_DIRECT:
            result = proxy_direct_client(client_socket, &session);
            break;
        case ROUTE_ACTION_REJECT:
            if (session.handshake_type == CLIENT_HANDSHAKE_SOCKS5) {
                send_socks_reply(client_socket, 0x02);
            } else if (session.handshake_type == CLIENT_HANDSHAKE_HTTP_CONNECT) {
                send_http_connect_reply(client_socket, 403);
            } else {
                send_http_forward_error(client_socket, 403, "Forbidden");
            }
            result = -1;
            break;
        default:
            if (session.handshake_type == CLIENT_HANDSHAKE_SOCKS5) {
                send_socks_reply(client_socket, 0x07);
            } else if (session.handshake_type == CLIENT_HANDSHAKE_HTTP_CONNECT) {
                send_http_connect_reply(client_socket, 502);
            } else {
                send_http_forward_error(client_socket, 502, "Bad Gateway");
            }
            break;
    }

    shutdown(client_socket, SD_BOTH);
    closesocket(client_socket);

    if (result != 0) {
        printf("Closed %s with error\n", destination_text);
    } else {
        printf("Closed %s\n", destination_text);
    }
    fflush(stdout);

#if PLATFORM_IS_WINDOWS
    return 0;
#else
    return NULL;
#endif
}

static SOCKET create_listener(const char* bind_addr, int port) {
    struct addrinfo hints;
    struct addrinfo* result = NULL;
    struct addrinfo* item = NULL;
    char port_string[16];
    SOCKET server_socket = INVALID_SOCKET;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    snprintf(port_string, sizeof(port_string), "%d", port);

    if (getaddrinfo(bind_addr, port_string, &hints, &result) != 0) {
        return INVALID_SOCKET;
    }

    for (item = result; item != NULL; item = item->ai_next) {
        int reuse = 1;
        server_socket = socket(item->ai_family, item->ai_socktype, item->ai_protocol);
        if (server_socket == INVALID_SOCKET) {
            continue;
        }

        setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

        if (bind(server_socket, item->ai_addr, (int)item->ai_addrlen) == 0 &&
            listen(server_socket, SOMAXCONN) == 0) {
            break;
        }

        closesocket(server_socket);
        server_socket = INVALID_SOCKET;
    }

    freeaddrinfo(result);
    return server_socket;
}

int start_proxy(const Config* config) {
    SOCKET server_socket = create_listener(config->local_bind_addr, config->local_port);

    if (server_socket == INVALID_SOCKET) {
        fprintf(stderr, "Failed to listen on %s:%d\n", config->local_bind_addr, config->local_port);
        return -1;
    }

    printf("%s proxy listening on %s:%d\n", inbound_type_name(config->type), config->local_bind_addr, config->local_port);
    fflush(stdout);

    for (;;) {
        SOCKET client_socket = accept(server_socket, NULL, NULL);
        ClientThreadArgs* args = NULL;

        if (client_socket == INVALID_SOCKET) {
            fprintf(stderr, "accept failed: %d\n", WSAGetLastError());
            continue;
        }

        args = (ClientThreadArgs*)malloc(sizeof(*args));
        if (args == NULL) {
            closesocket(client_socket);
            continue;
        }

        args->client_socket = client_socket;
        args->config = config;

#if PLATFORM_IS_WINDOWS
        {
            HANDLE worker = (HANDLE)_beginthreadex(NULL, 0, client_thread_main, args, 0, NULL);
            if (worker == NULL) {
                free(args);
                closesocket(client_socket);
                continue;
            }

            CloseHandle(worker);
        }
#else
        {
            pthread_t worker;
            if (pthread_create(&worker, NULL, client_thread_main, args) != 0) {
                free(args);
                closesocket(client_socket);
                continue;
            }

            pthread_detach(worker);
        }
#endif
    }

    closesocket(server_socket);
    return 0;
}
