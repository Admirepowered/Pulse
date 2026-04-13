#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "outbounds/stream.h"

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

static int raw_send_all(RemoteStream* stream, const uint8_t* data, size_t len) {
    size_t sent_total = 0;

    while (sent_total < len) {
        if (stream->use_tls) {
            int sent = SSL_write(stream->ssl, data + sent_total, (int)(len - sent_total));
            if (sent <= 0) {
                return -1;
            }
            sent_total += (size_t)sent;
        } else {
            int sent = send(stream->socket_fd, (const char*)data + sent_total, (int)(len - sent_total), 0);
            if (sent == SOCKET_ERROR || sent == 0) {
                return -1;
            }
            sent_total += (size_t)sent;
        }
    }

    return 0;
}

static int raw_recv_some(RemoteStream* stream, uint8_t* data, size_t len) {
    if (stream->use_tls) {
        return SSL_read(stream->ssl, data, (int)len);
    }
    return recv(stream->socket_fd, (char*)data, (int)len, 0);
}

static int raw_recv_exact(RemoteStream* stream, uint8_t* data, size_t len) {
    size_t received_total = 0;

    while (received_total < len) {
        int received = raw_recv_some(stream, data + received_total, len - received_total);
        if (received <= 0) {
            return -1;
        }
        received_total += (size_t)received;
    }

    return 0;
}

static int discard_exact(RemoteStream* stream, uint64_t len) {
    uint8_t buffer[512];

    while (len > 0) {
        size_t chunk = len > sizeof(buffer) ? sizeof(buffer) : (size_t)len;
        if (raw_recv_exact(stream, buffer, chunk) != 0) {
            return -1;
        }
        len -= chunk;
    }

    return 0;
}

static int stream_send_frame(RemoteStream* stream, uint8_t opcode, const uint8_t* payload, size_t len) {
    uint8_t header[14];
    uint8_t mask[4];
    size_t header_len = 0;
    uint8_t* masked_payload = NULL;
    size_t i = 0;

    if (!stream->use_ws) {
        return raw_send_all(stream, payload, len);
    }

    header[0] = 0x80 | (opcode & 0x0f);
    header_len = 2;

    if (len < 126) {
        header[1] = 0x80 | (uint8_t)len;
    } else if (len <= 0xffff) {
        header[1] = 0x80 | 126;
        header[2] = (uint8_t)((len >> 8) & 0xff);
        header[3] = (uint8_t)(len & 0xff);
        header_len = 4;
    } else {
        uint64_t long_len = (uint64_t)len;
        int shift = 0;
        header[1] = 0x80 | 127;
        for (shift = 7; shift >= 0; --shift) {
            header[2 + (7 - shift)] = (uint8_t)((long_len >> (shift * 8)) & 0xff);
        }
        header_len = 10;
    }

    if (RAND_bytes(mask, sizeof(mask)) != 1) {
        for (i = 0; i < sizeof(mask); ++i) {
            mask[i] = (uint8_t)(rand() & 0xff);
        }
    }

    memcpy(header + header_len, mask, sizeof(mask));
    header_len += sizeof(mask);

    if (raw_send_all(stream, header, header_len) != 0) {
        return -1;
    }

    if (len == 0) {
        return 0;
    }

    masked_payload = (uint8_t*)malloc(len);
    if (masked_payload == NULL) {
        return -1;
    }

    for (i = 0; i < len; ++i) {
        masked_payload[i] = payload[i] ^ mask[i % 4];
    }

    if (raw_send_all(stream, masked_payload, len) != 0) {
        free(masked_payload);
        return -1;
    }

    free(masked_payload);
    return 0;
}

static int consume_ws_control_frame(RemoteStream* stream, uint8_t opcode, uint64_t payload_len) {
    uint8_t payload[125];

    if (payload_len > sizeof(payload)) {
        if (discard_exact(stream, payload_len) != 0) {
            return -1;
        }
        return opcode == 0x08 ? 0 : 1;
    }

    if (payload_len > 0 && raw_recv_exact(stream, payload, (size_t)payload_len) != 0) {
        return -1;
    }

    if (opcode == 0x09) {
        if (stream_send_frame(stream, 0x0A, payload, (size_t)payload_len) != 0) {
            return -1;
        }
        return 1;
    }

    if (opcode == 0x08) {
        return 0;
    }

    return 1;
}

static int read_http_response_headers(RemoteStream* stream, char* response, size_t response_size) {
    size_t offset = 0;

    while (offset + 1 < response_size) {
        if (raw_recv_exact(stream, (uint8_t*)&response[offset], 1) != 0) {
            return -1;
        }
        ++offset;
        response[offset] = '\0';

        if (offset >= 4 && memcmp(response + offset - 4, "\r\n\r\n", 4) == 0) {
            return 0;
        }
    }

    return -1;
}

static int starts_with_ci(const char* text, const char* prefix) {
    size_t i = 0;

    for (i = 0; prefix[i] != '\0'; ++i) {
        if (text[i] == '\0') {
            return 0;
        }
        if (tolower((unsigned char)text[i]) != tolower((unsigned char)prefix[i])) {
            return 0;
        }
    }

    return 1;
}

static int get_http_header_value(const char* response, const char* name, char* out, size_t out_size) {
    const char* line = response;
    size_t name_len = strlen(name);

    while (*line != '\0') {
        const char* line_end = strstr(line, "\r\n");
        const char* value_start = NULL;
        size_t value_len = 0;

        if (line_end == NULL || line_end == line) {
            break;
        }

        if ((size_t)(line_end - line) > name_len + 1 && starts_with_ci(line, name) && line[name_len] == ':') {
            value_start = line + name_len + 1;
            while (value_start < line_end && isspace((unsigned char)*value_start)) {
                ++value_start;
            }
            value_len = (size_t)(line_end - value_start);
            if (value_len >= out_size) {
                value_len = out_size - 1;
            }
            memcpy(out, value_start, value_len);
            out[value_len] = '\0';
            return 1;
        }

        line = line_end + 2;
    }

    return 0;
}

SOCKET connect_tcp_socket(const char* host, int port) {
    struct addrinfo hints;
    struct addrinfo* result = NULL;
    struct addrinfo* item = NULL;
    char port_string[16];
    SOCKET socket_fd = INVALID_SOCKET;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    snprintf(port_string, sizeof(port_string), "%d", port);

    if (getaddrinfo(host, port_string, &hints, &result) != 0) {
        return INVALID_SOCKET;
    }

    for (item = result; item != NULL; item = item->ai_next) {
        socket_fd = socket(item->ai_family, item->ai_socktype, item->ai_protocol);
        if (socket_fd == INVALID_SOCKET) {
            continue;
        }

        if (connect(socket_fd, item->ai_addr, (int)item->ai_addrlen) == 0) {
            break;
        }

        closesocket(socket_fd);
        socket_fd = INVALID_SOCKET;
    }

    freeaddrinfo(result);
    return socket_fd;
}

int remote_stream_connect(RemoteStream* stream, const char* host, int port) {
    memset(stream, 0, sizeof(*stream));
    stream->socket_fd = connect_tcp_socket(host, port);
    return stream->socket_fd == INVALID_SOCKET ? -1 : 0;
}

int remote_stream_enable_tls(RemoteStream* stream, const char* tls_host, int skip_cert_verify) {
    stream->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (stream->ssl_ctx == NULL) {
        return -1;
    }

    SSL_CTX_set_mode(stream->ssl_ctx, SSL_MODE_AUTO_RETRY);

    if (skip_cert_verify) {
        SSL_CTX_set_verify(stream->ssl_ctx, SSL_VERIFY_NONE, NULL);
    } else {
        SSL_CTX_set_verify(stream->ssl_ctx, SSL_VERIFY_PEER, NULL);
        if (SSL_CTX_set_default_verify_paths(stream->ssl_ctx) != 1) {
            return -1;
        }
    }

    stream->ssl = SSL_new(stream->ssl_ctx);
    if (stream->ssl == NULL) {
        return -1;
    }

    if (SSL_set_fd(stream->ssl, (int)stream->socket_fd) != 1) {
        return -1;
    }

    if (SSL_set_tlsext_host_name(stream->ssl, tls_host) != 1) {
        return -1;
    }

    if (!skip_cert_verify && SSL_set1_host(stream->ssl, tls_host) != 1) {
        return -1;
    }

    if (SSL_connect(stream->ssl) != 1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    stream->use_tls = 1;
    return 0;
}

int remote_stream_start_websocket(RemoteStream* stream, const char* path, const char* host) {
    unsigned char nonce[16];
    unsigned char sha1_digest[SHA_DIGEST_LENGTH];
    char ws_key[32];
    char accept_seed[96];
    char expected_accept[64];
    char response[PULSE_HTTP_BUFFER_SIZE];
    char actual_accept[64];
    char request[2048];

    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        return -1;
    }

    EVP_EncodeBlock((unsigned char*)ws_key, nonce, (int)sizeof(nonce));
    snprintf(accept_seed, sizeof(accept_seed), "%s%s", ws_key, WS_GUID);
    SHA1((const unsigned char*)accept_seed, strlen(accept_seed), sha1_digest);
    EVP_EncodeBlock((unsigned char*)expected_accept, sha1_digest, SHA_DIGEST_LENGTH);

    snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "User-Agent: Pulse/1.0\r\n"
        "\r\n",
        path,
        host,
        ws_key);

    if (raw_send_all(stream, (const uint8_t*)request, strlen(request)) != 0) {
        return -1;
    }

    if (read_http_response_headers(stream, response, sizeof(response)) != 0) {
        return -1;
    }

    if (strstr(response, " 101 ") == NULL) {
        fprintf(stderr, "WebSocket upgrade failed:\n%s\n", response);
        return -1;
    }

    if (!get_http_header_value(response, "Sec-WebSocket-Accept", actual_accept, sizeof(actual_accept))) {
        fprintf(stderr, "Missing Sec-WebSocket-Accept header.\n");
        return -1;
    }

    if (strcmp(actual_accept, expected_accept) != 0) {
        fprintf(stderr, "WebSocket accept header mismatch.\n");
        return -1;
    }

    stream->use_ws = 1;
    return 0;
}

int remote_stream_send(RemoteStream* stream, const uint8_t* payload, size_t len) {
    if (stream->use_ws) {
        return stream_send_frame(stream, 0x02, payload, len);
    }
    return raw_send_all(stream, payload, len);
}

int remote_stream_recv(RemoteStream* stream, uint8_t* out, size_t len) {
    if (!stream->use_ws) {
        return raw_recv_some(stream, out, len);
    }

    for (;;) {
        if (stream->ws_payload_remaining == 0) {
            uint8_t header[2];
            uint8_t extended_len[8];
            uint64_t payload_len = 0;
            uint8_t opcode = 0;

            if (raw_recv_exact(stream, header, sizeof(header)) != 0) {
                return -1;
            }

            opcode = header[0] & 0x0f;
            payload_len = (uint64_t)(header[1] & 0x7f);
            stream->ws_payload_masked = (header[1] & 0x80) != 0;

            if (payload_len == 126) {
                if (raw_recv_exact(stream, extended_len, 2) != 0) {
                    return -1;
                }
                payload_len = ((uint64_t)extended_len[0] << 8) | (uint64_t)extended_len[1];
            } else if (payload_len == 127) {
                size_t i = 0;
                if (raw_recv_exact(stream, extended_len, 8) != 0) {
                    return -1;
                }
                payload_len = 0;
                for (i = 0; i < 8; ++i) {
                    payload_len = (payload_len << 8) | (uint64_t)extended_len[i];
                }
            }

            if (stream->ws_payload_masked) {
                if (raw_recv_exact(stream, stream->ws_mask, sizeof(stream->ws_mask)) != 0) {
                    return -1;
                }
                stream->ws_mask_offset = 0;
            }

            if (opcode == 0x08 || opcode == 0x09 || opcode == 0x0A) {
                int control_result = consume_ws_control_frame(stream, opcode, payload_len);
                if (control_result <= 0) {
                    return control_result;
                }
                continue;
            }

            if (opcode != 0x02 && opcode != 0x00) {
                if (discard_exact(stream, payload_len) != 0) {
                    return -1;
                }
                continue;
            }

            if (payload_len == 0) {
                continue;
            }

            stream->ws_payload_remaining = payload_len;
        }

        if (stream->ws_payload_remaining > 0) {
            size_t chunk = stream->ws_payload_remaining > len ? len : (size_t)stream->ws_payload_remaining;
            size_t i = 0;
            int received = raw_recv_some(stream, out, chunk);
            if (received <= 0) {
                return -1;
            }

            if (stream->ws_payload_masked) {
                for (i = 0; i < (size_t)received; ++i) {
                    out[i] ^= stream->ws_mask[(stream->ws_mask_offset + i) % 4];
                }
                stream->ws_mask_offset += (size_t)received;
            }

            stream->ws_payload_remaining -= (uint64_t)received;
            return received;
        }
    }
}

int remote_stream_recv_exact(RemoteStream* stream, uint8_t* out, size_t len) {
    size_t received_total = 0;

    while (received_total < len) {
        int received = remote_stream_recv(stream, out + received_total, len - received_total);
        if (received <= 0) {
            return -1;
        }
        received_total += (size_t)received;
    }

    return 0;
}

int remote_stream_has_pending_data(const RemoteStream* stream) {
    if (stream->ws_payload_remaining > 0) {
        return 1;
    }

    if (stream->use_tls && stream->ssl != NULL && SSL_pending(stream->ssl) > 0) {
        return 1;
    }

    return 0;
}

void remote_stream_shutdown(RemoteStream* stream) {
    if (stream->socket_fd != INVALID_SOCKET) {
        shutdown(stream->socket_fd, SD_BOTH);
    }
}

void remote_stream_close(RemoteStream* stream) {
    if (stream == NULL) {
        return;
    }

    if (stream->socket_fd != INVALID_SOCKET) {
        shutdown(stream->socket_fd, SD_BOTH);
    }

    if (stream->ssl != NULL) {
        SSL_free(stream->ssl);
        stream->ssl = NULL;
    }

    if (stream->ssl_ctx != NULL) {
        SSL_CTX_free(stream->ssl_ctx);
        stream->ssl_ctx = NULL;
    }

    if (stream->socket_fd != INVALID_SOCKET) {
        closesocket(stream->socket_fd);
        stream->socket_fd = INVALID_SOCKET;
    }
}
