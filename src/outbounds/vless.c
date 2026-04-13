#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "core/proxy.h"
#include "outbounds/stream.h"

static int hex_value(int ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

static int uuid_to_bytes(const char* uuid, uint8_t out[16]) {
    char compact[33];
    size_t compact_index = 0;
    size_t i = 0;

    for (i = 0; uuid[i] != '\0'; ++i) {
        if (uuid[i] == '-') {
            continue;
        }
        if (!isxdigit((unsigned char)uuid[i]) || compact_index >= sizeof(compact) - 1) {
            return -1;
        }
        compact[compact_index++] = uuid[i];
    }

    if (compact_index != 32) {
        return -1;
    }

    compact[compact_index] = '\0';

    for (i = 0; i < 16; ++i) {
        int hi = hex_value(compact[i * 2]);
        int lo = hex_value(compact[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }

    return 0;
}

static int send_vless_request(RemoteStream* stream, const EndpointConfig* endpoint, const Destination* destination) {
    uint8_t uuid[16];
    uint8_t request[1 + 16 + 1 + 1 + 2 + 1 + 1 + 255];
    size_t offset = 0;

    if (uuid_to_bytes(endpoint->vless.uuid, uuid) != 0) {
        return -1;
    }

    request[offset++] = 0x00;
    memcpy(request + offset, uuid, sizeof(uuid));
    offset += sizeof(uuid);
    request[offset++] = 0x00;
    request[offset++] = 0x01;
    request[offset++] = (uint8_t)((destination->port >> 8) & 0xff);
    request[offset++] = (uint8_t)(destination->port & 0xff);
    request[offset++] = (uint8_t)destination->type;

    if (destination->type == DEST_ADDR_DOMAIN) {
        size_t host_len = strlen(destination->host);
        if (host_len == 0 || host_len > 255) {
            return -1;
        }
        request[offset++] = (uint8_t)host_len;
        memcpy(request + offset, destination->host, host_len);
        offset += host_len;
    } else {
        memcpy(request + offset, destination->raw_addr, destination->raw_addr_len);
        offset += destination->raw_addr_len;
    }

    return remote_stream_send(stream, request, offset);
}

static int expect_vless_response(RemoteStream* stream) {
    uint8_t header[2];

    if (remote_stream_recv_exact(stream, header, sizeof(header)) != 0) {
        return -1;
    }

    if (header[0] != 0x00) {
        fprintf(stderr, "Unexpected VLESS response version: %u\n", header[0]);
        return -1;
    }

    if (header[1] > 0) {
        uint8_t* addons = (uint8_t*)malloc(header[1]);
        if (addons == NULL) {
            return -1;
        }
        if (remote_stream_recv_exact(stream, addons, header[1]) != 0) {
            free(addons);
            return -1;
        }
        free(addons);
    }

    return 0;
}

static int open_remote_stream(RemoteStream* stream, const EndpointConfig* endpoint, const Destination* destination) {
    if (remote_stream_connect(stream, endpoint->server, endpoint->port) != 0) {
        fprintf(stderr, "Failed to connect to upstream %s:%d\n", endpoint->server, endpoint->port);
        return -1;
    }

    if (endpoint->vless.tls &&
        remote_stream_enable_tls(stream,
            endpoint->vless.servername[0] != '\0' ? endpoint->vless.servername : endpoint->server,
            endpoint->skip_cert_verify) != 0) {
        fprintf(stderr, "TLS handshake failed.\n");
        remote_stream_close(stream);
        return -1;
    }

    if (_stricmp(endpoint->vless.network, "ws") == 0 &&
        remote_stream_start_websocket(stream,
            endpoint->vless.ws.path[0] != '\0' ? endpoint->vless.ws.path : "/",
            endpoint->vless.ws.host[0] != '\0' ? endpoint->vless.ws.host : endpoint->server) != 0) {
        fprintf(stderr, "WebSocket handshake failed.\n");
        remote_stream_close(stream);
        return -1;
    }

    if (send_vless_request(stream, endpoint, destination) != 0) {
        fprintf(stderr, "Failed to send VLESS request.\n");
        remote_stream_close(stream);
        return -1;
    }

    return 0;
}

int proxy_vless_client(SOCKET client_socket, const EndpointConfig* endpoint, const ProxySession* session) {
    RemoteStream remote_stream;
    const Destination* destination = &session->destination;
    uint8_t buffer[PULSE_IO_BUFFER_SIZE];
    int vless_response_ready = 0;

    if (open_remote_stream(&remote_stream, endpoint, destination) != 0) {
        if (session->handshake_type == CLIENT_HANDSHAKE_SOCKS5) {
            send_socks_reply(client_socket, 0x05);
        } else if (session->handshake_type == CLIENT_HANDSHAKE_HTTP_CONNECT) {
            send_http_connect_reply(client_socket, 502);
        } else {
            send_http_forward_error(client_socket, 502, "Bad Gateway");
        }
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
    } else if (session->initial_data_len > 0) {
        if (remote_stream_send(&remote_stream, session->initial_data, session->initial_data_len) != 0) {
            remote_stream_close(&remote_stream);
            return -1;
        }
    }

    for (;;) {
        fd_set read_fds;
        int client_ready = 0;
        int remote_ready = 0;

        if (remote_stream_has_pending_data(&remote_stream)) {
            remote_ready = 1;
        } else {
            FD_ZERO(&read_fds);
            FD_SET(client_socket, &read_fds);
            FD_SET(remote_stream.socket_fd, &read_fds);

            SOCKET max_socket = client_socket > remote_stream.socket_fd ? client_socket : remote_stream.socket_fd;

            if (select((int)(max_socket + 1), &read_fds, NULL, NULL, NULL) == SOCKET_ERROR) {
                break;
            }

            client_ready = FD_ISSET(client_socket, &read_fds);
            remote_ready = FD_ISSET(remote_stream.socket_fd, &read_fds);
        }

        if (client_ready) {
            int received = recv(client_socket, (char*)buffer, sizeof(buffer), 0);
            if (received <= 0) {
                break;
            }

            if (remote_stream_send(&remote_stream, buffer, (size_t)received) != 0) {
                break;
            }
        }

        if (remote_ready) {
            int received = 0;

            if (!vless_response_ready) {
                if (expect_vless_response(&remote_stream) != 0) {
                    fprintf(stderr, "VLESS upstream rejected the request.\n");
                    break;
                }
                vless_response_ready = 1;

                if (!remote_stream_has_pending_data(&remote_stream)) {
                    continue;
                }
            }

            received = remote_stream_recv(&remote_stream, buffer, sizeof(buffer));
            if (received <= 0) {
                break;
            }

            if (send_all_socket(client_socket, buffer, (size_t)received) != 0) {
                break;
            }
        }
    }

    remote_stream_shutdown(&remote_stream);
    remote_stream_close(&remote_stream);
    return 0;
}
