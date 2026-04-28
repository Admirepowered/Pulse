#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "core/proxy.h"
#include "outbounds/stream.h"
#include "outbounds/protocol_helpers.h"

#define ANYTLS_CMD_WASTE 0
#define ANYTLS_CMD_SYN 1
#define ANYTLS_CMD_PSH 2
#define ANYTLS_CMD_FIN 3
#define ANYTLS_CMD_SETTINGS 4
#define ANYTLS_CMD_ALERT 5
#define ANYTLS_CMD_UPDATE_PADDING_SCHEME 6
#define ANYTLS_CMD_SYNACK 7
#define ANYTLS_CMD_HEART_REQUEST 8
#define ANYTLS_CMD_HEART_RESPONSE 9
#define ANYTLS_CMD_SERVER_SETTINGS 10
#define ANYTLS_HEADER_SIZE 7
#define ANYTLS_MAX_FRAME_PAYLOAD 65535

typedef struct {
    uint8_t cmd;
    uint32_t sid;
    uint16_t len;
} AnyTlsFrameHeader;

static const char ANYTLS_DEFAULT_PADDING_SCHEME[] =
    "stop=8\n"
    "0=30-30\n"
    "1=100-400\n"
    "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n"
    "3=9-9,500-1000\n"
    "4=500-1000\n"
    "5=500-1000\n"
    "6=500-1000\n"
    "7=500-1000";

static int report_anytls_failure(SOCKET client_socket, const ProxySession* session) {
    if (session->handshake_type == CLIENT_HANDSHAKE_SOCKS5) {
        send_socks_reply(client_socket, 0x05);
    } else if (session->handshake_type == CLIENT_HANDSHAKE_HTTP_CONNECT) {
        send_http_connect_reply(client_socket, 502);
    } else {
        send_http_forward_error(client_socket, 502, "Bad Gateway");
    }
    return -1;
}

static void anytls_write_be16(uint8_t out[2], uint16_t value) {
    out[0] = (uint8_t)((value >> 8) & 0xff);
    out[1] = (uint8_t)(value & 0xff);
}

static void anytls_write_be32(uint8_t out[4], uint32_t value) {
    out[0] = (uint8_t)((value >> 24) & 0xff);
    out[1] = (uint8_t)((value >> 16) & 0xff);
    out[2] = (uint8_t)((value >> 8) & 0xff);
    out[3] = (uint8_t)(value & 0xff);
}

static void anytls_md5_hex_lower(const uint8_t* data, size_t len, char out[33]) {
    uint8_t digest[MD5_DIGEST_LENGTH];
    static const char hex[] = "0123456789abcdef";
    size_t i = 0;

    MD5(data, len, digest);
    for (i = 0; i < sizeof(digest); ++i) {
        out[i * 2] = hex[(digest[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    out[32] = '\0';
}

static int anytls_send_frame(RemoteStream* stream, uint8_t cmd, uint32_t sid, const uint8_t* data, size_t data_len) {
    uint8_t header[ANYTLS_HEADER_SIZE];

    if (data_len > ANYTLS_MAX_FRAME_PAYLOAD) {
        return -1;
    }

    header[0] = cmd;
    anytls_write_be32(header + 1, sid);
    anytls_write_be16(header + 5, (uint16_t)data_len);

    if (remote_stream_send(stream, header, sizeof(header)) != 0) {
        return -1;
    }
    if (data_len > 0 && remote_stream_send(stream, data, data_len) != 0) {
        return -1;
    }
    return 0;
}

static int anytls_recv_header(RemoteStream* stream, AnyTlsFrameHeader* header) {
    uint8_t raw[ANYTLS_HEADER_SIZE];

    if (remote_stream_recv_exact(stream, raw, sizeof(raw)) != 0) {
        return -1;
    }

    header->cmd = raw[0];
    header->sid = ((uint32_t)raw[1] << 24) |
        ((uint32_t)raw[2] << 16) |
        ((uint32_t)raw[3] << 8) |
        (uint32_t)raw[4];
    header->len = (uint16_t)(((uint16_t)raw[5] << 8) | (uint16_t)raw[6]);
    return 0;
}

static int anytls_recv_payload(RemoteStream* stream, const AnyTlsFrameHeader* header, uint8_t* out, size_t out_size) {
    if (header->len == 0) {
        return 0;
    }
    if (header->len > out_size) {
        return -1;
    }
    return remote_stream_recv_exact(stream, out, header->len);
}

static int anytls_discard_payload(RemoteStream* stream, uint16_t len) {
    uint8_t buffer[512];
    uint16_t remaining = len;

    while (remaining > 0) {
        size_t chunk = remaining > sizeof(buffer) ? sizeof(buffer) : remaining;
        if (remote_stream_recv_exact(stream, buffer, chunk) != 0) {
            return -1;
        }
        remaining = (uint16_t)(remaining - chunk);
    }
    return 0;
}

static int anytls_open_stream(RemoteStream* stream, const EndpointConfig* endpoint) {
    const char* tls_host = endpoint->anytls.servername[0] != '\0' ? endpoint->anytls.servername : endpoint->server;

    if (remote_stream_connect(stream, endpoint->server, endpoint->port) != 0) {
        fprintf(stderr, "Failed to connect to AnyTLS upstream %s:%d\n", endpoint->server, endpoint->port);
        return -1;
    }

    if (endpoint->anytls.tls && remote_stream_enable_tls(stream, tls_host, endpoint->skip_cert_verify) != 0) {
        fprintf(stderr, "AnyTLS TLS handshake failed.\n");
        remote_stream_close(stream);
        return -1;
    }

    return 0;
}

static int anytls_send_client_auth(RemoteStream* stream, const EndpointConfig* endpoint) {
    uint8_t auth[32 + 2 + 30];
    uint8_t password_hash[SHA256_DIGEST_LENGTH];

    SHA256((const unsigned char*)endpoint->anytls.password, strlen(endpoint->anytls.password), password_hash);
    memcpy(auth, password_hash, sizeof(password_hash));
    anytls_write_be16(auth + sizeof(password_hash), 30);
    memset(auth + sizeof(password_hash) + 2, 0, 30);
    return remote_stream_send(stream, auth, sizeof(auth));
}

static int anytls_send_settings(RemoteStream* stream) {
    char md5_hex[33];
    char settings[512];
    int len = 0;

    anytls_md5_hex_lower((const uint8_t*)ANYTLS_DEFAULT_PADDING_SCHEME, strlen(ANYTLS_DEFAULT_PADDING_SCHEME), md5_hex);
    len = snprintf(settings, sizeof(settings),
        "v=2\n"
        "client=Pulse/1.0\n"
        "padding-md5=%s",
        md5_hex);
    if (len <= 0 || (size_t)len >= sizeof(settings)) {
        return -1;
    }

    return anytls_send_frame(stream, ANYTLS_CMD_SETTINGS, 0, (const uint8_t*)settings, (size_t)len);
}

static int anytls_send_syn(RemoteStream* stream, uint32_t sid) {
    return anytls_send_frame(stream, ANYTLS_CMD_SYN, sid, NULL, 0);
}

static int anytls_send_destination(RemoteStream* stream, uint32_t sid, const Destination* destination) {
    uint8_t addr[300];
    size_t addr_len = 0;

    if (encode_destination_streamaddr(destination, addr, sizeof(addr), &addr_len) != 0) {
        return -1;
    }

    return anytls_send_frame(stream, ANYTLS_CMD_PSH, sid, addr, addr_len);
}

static int anytls_send_fin(RemoteStream* stream, uint32_t sid) {
    return anytls_send_frame(stream, ANYTLS_CMD_FIN, sid, NULL, 0);
}

static int anytls_send_data(RemoteStream* stream, uint32_t sid, const uint8_t* data, size_t data_len) {
    size_t offset = 0;

    while (offset < data_len) {
        size_t chunk_len = data_len - offset;
        if (chunk_len > ANYTLS_MAX_FRAME_PAYLOAD) {
            chunk_len = ANYTLS_MAX_FRAME_PAYLOAD;
        }
        if (anytls_send_frame(stream, ANYTLS_CMD_PSH, sid, data + offset, chunk_len) != 0) {
            return -1;
        }
        offset += chunk_len;
    }

    return 0;
}

static int anytls_drain_control_frames(RemoteStream* stream, uint32_t sid, uint8_t* out, size_t out_size, size_t* out_len, int* remote_closed) {
    AnyTlsFrameHeader header;
    uint8_t control[1024];

    *out_len = 0;

    for (;;) {
        if (anytls_recv_header(stream, &header) != 0) {
            return -1;
        }

        if (header.cmd == ANYTLS_CMD_PSH && header.sid == sid) {
            if (header.len > out_size || anytls_recv_payload(stream, &header, out, out_size) != 0) {
                return -1;
            }
            *out_len = header.len;
            return 0;
        }

        if (header.cmd == ANYTLS_CMD_FIN && header.sid == sid) {
            if (header.len > 0 && anytls_discard_payload(stream, header.len) != 0) {
                return -1;
            }
            *remote_closed = 1;
            return 0;
        }

        if (header.len > sizeof(control)) {
            if (anytls_discard_payload(stream, header.len) != 0) {
                return -1;
            }
            if (header.cmd == ANYTLS_CMD_ALERT) {
                fprintf(stderr, "AnyTLS server sent an oversized alert.\n");
                return -1;
            }
            continue;
        }

        if (anytls_recv_payload(stream, &header, control, sizeof(control)) != 0) {
            return -1;
        }

        switch (header.cmd) {
            case ANYTLS_CMD_WASTE:
            case ANYTLS_CMD_SETTINGS:
            case ANYTLS_CMD_UPDATE_PADDING_SCHEME:
            case ANYTLS_CMD_SERVER_SETTINGS:
                break;
            case ANYTLS_CMD_HEART_REQUEST:
                if (anytls_send_frame(stream, ANYTLS_CMD_HEART_RESPONSE, header.sid, NULL, 0) != 0) {
                    return -1;
                }
                break;
            case ANYTLS_CMD_HEART_RESPONSE:
                break;
            case ANYTLS_CMD_SYNACK:
                if (header.sid == sid && header.len > 0) {
                    fprintf(stderr, "AnyTLS upstream rejected stream: %.*s\n", header.len, (const char*)control);
                    return -1;
                }
                break;
            case ANYTLS_CMD_ALERT:
                fprintf(stderr, "AnyTLS server alert: %.*s\n", header.len, (const char*)control);
                return -1;
            default:
                break;
        }
    }
}

static int anytls_expect_open_sequence(RemoteStream* stream, uint32_t sid) {
    AnyTlsFrameHeader header;
    uint8_t payload[1024];
    int saw_server_settings = 0;
    int saw_synack = 0;

    while (!saw_synack) {
        if (anytls_recv_header(stream, &header) != 0) {
            return -1;
        }
        if (header.len > sizeof(payload)) {
            if (anytls_discard_payload(stream, header.len) != 0) {
                return -1;
            }
            fprintf(stderr, "AnyTLS control frame too large during handshake.\n");
            return -1;
        }
        if (anytls_recv_payload(stream, &header, payload, sizeof(payload)) != 0) {
            return -1;
        }

        switch (header.cmd) {
            case ANYTLS_CMD_SERVER_SETTINGS:
                saw_server_settings = 1;
                break;
            case ANYTLS_CMD_SYNACK:
                if (header.sid != sid) {
                    continue;
                }
                if (header.len > 0) {
                    fprintf(stderr, "AnyTLS SYNACK error: %.*s\n", header.len, (const char*)payload);
                    return -1;
                }
                saw_synack = 1;
                break;
            case ANYTLS_CMD_HEART_REQUEST:
                if (anytls_send_frame(stream, ANYTLS_CMD_HEART_RESPONSE, header.sid, NULL, 0) != 0) {
                    return -1;
                }
                break;
            case ANYTLS_CMD_UPDATE_PADDING_SCHEME:
            case ANYTLS_CMD_WASTE:
            case ANYTLS_CMD_HEART_RESPONSE:
                break;
            case ANYTLS_CMD_ALERT:
                fprintf(stderr, "AnyTLS server alert: %.*s\n", header.len, (const char*)payload);
                return -1;
            default:
                if (!saw_server_settings && header.cmd == ANYTLS_CMD_PSH && header.sid == sid) {
                    return -1;
                }
                break;
        }
    }

    return 0;
}

int proxy_anytls_client(SOCKET client_socket, const EndpointConfig* endpoint, const ProxySession* session) {
    RemoteStream remote_stream;
    uint8_t buffer[PULSE_IO_BUFFER_SIZE];
    size_t plain_len = 0;
    int remote_closed = 0;
    const uint32_t sid = 1;

    if (anytls_open_stream(&remote_stream, endpoint) != 0) {
        return report_anytls_failure(client_socket, session);
    }

    if (anytls_send_client_auth(&remote_stream, endpoint) != 0 ||
        anytls_send_settings(&remote_stream) != 0 ||
        anytls_send_syn(&remote_stream, sid) != 0 ||
        anytls_send_destination(&remote_stream, sid, &session->destination) != 0 ||
        anytls_expect_open_sequence(&remote_stream, sid) != 0) {
        remote_stream_close(&remote_stream);
        return report_anytls_failure(client_socket, session);
    }

    if (session->initial_data_len > 0 &&
        anytls_send_data(&remote_stream, sid, session->initial_data, session->initial_data_len) != 0) {
        remote_stream_close(&remote_stream);
        return report_anytls_failure(client_socket, session);
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

            {
                SOCKET max_socket = client_socket > remote_stream.socket_fd ? client_socket : remote_stream.socket_fd;
                if (select((int)(max_socket + 1), &read_fds, NULL, NULL, NULL) == SOCKET_ERROR) {
                    break;
                }
            }

            client_ready = FD_ISSET(client_socket, &read_fds);
            remote_ready = FD_ISSET(remote_stream.socket_fd, &read_fds);
        }

        if (client_ready) {
            int received = recv(client_socket, (char*)buffer, sizeof(buffer), 0);
            if (received <= 0) {
                anytls_send_fin(&remote_stream, sid);
                break;
            }
            if (anytls_send_data(&remote_stream, sid, buffer, (size_t)received) != 0) {
                break;
            }
        }

        if (remote_ready) {
            if (anytls_drain_control_frames(&remote_stream, sid, buffer, sizeof(buffer), &plain_len, &remote_closed) != 0) {
                break;
            }
            if (remote_closed) {
                break;
            }
            if (plain_len > 0 && send_all_socket(client_socket, buffer, plain_len) != 0) {
                break;
            }
        }
    }

    remote_stream_shutdown(&remote_stream);
    remote_stream_close(&remote_stream);
    return 0;
}
