#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include "core/proxy.h"
#include "outbounds/stream.h"

#define VMESS_VERSION 0x01
#define VMESS_OPT_CHUNK_STREAM 0x01
#define VMESS_SEC_AES128_GCM 0x03
#define VMESS_SEC_CHACHA20_POLY1305 0x04
#define VMESS_SEC_NONE 0x05
#define VMESS_CMD_TCP 0x01
#define VMESS_AEAD_TAG_SIZE 16
#define VMESS_MAX_PLAIN_CHUNK 4096

typedef enum {
    VMESS_BODY_NONE = 0,
    VMESS_BODY_AES128_GCM,
    VMESS_BODY_CHACHA20_POLY1305
} VMessBodySecurity;

typedef struct {
    uint8_t request_body_key[16];
    uint8_t request_body_iv[16];
    uint8_t response_body_key[16];
    uint8_t response_body_iv[16];
    uint8_t response_header;
    uint32_t request_chunk_count;
    uint32_t response_chunk_count;
    VMessBodySecurity security;
} VMessSession;

static int report_vmess_failure(SOCKET client_socket, const ProxySession* session) {
    if (session->handshake_type == CLIENT_HANDSHAKE_SOCKS5) {
        send_socks_reply(client_socket, 0x05);
    } else if (session->handshake_type == CLIENT_HANDSHAKE_HTTP_CONNECT) {
        send_http_connect_reply(client_socket, 502);
    } else {
        send_http_forward_error(client_socket, 502, "Bad Gateway");
    }
    return -1;
}

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

static void write_be16(uint8_t out[2], uint16_t value) {
    out[0] = (uint8_t)((value >> 8) & 0xff);
    out[1] = (uint8_t)(value & 0xff);
}

static void write_be64(uint8_t out[8], uint64_t value) {
    int i = 0;
    for (i = 7; i >= 0; --i) {
        out[7 - i] = (uint8_t)((value >> (i * 8)) & 0xff);
    }
}

static uint32_t fnv1a32(const uint8_t* data, size_t len) {
    uint32_t hash = 2166136261u;
    size_t i = 0;

    for (i = 0; i < len; ++i) {
        hash ^= data[i];
        hash *= 16777619u;
    }

    return hash;
}

static void vmess_make_cmd_key(const uint8_t uuid[16], uint8_t out[16]) {
    static const char magic[] = "c48619fe-8f02-49e0-b9e9-edf763e17e21";
    EVP_MD_CTX* md = EVP_MD_CTX_new();

    EVP_DigestInit_ex(md, EVP_md5(), NULL);
    EVP_DigestUpdate(md, uuid, 16);
    EVP_DigestUpdate(md, magic, sizeof(magic) - 1);
    EVP_DigestFinal_ex(md, out, NULL);
    EVP_MD_CTX_free(md);
}

static void vmess_make_legacy_auth(const uint8_t uuid[16], uint8_t out[16], uint64_t timestamp) {
    uint8_t message[32];
    unsigned int out_len = 0;
    int i = 0;
    uint8_t ts[8];

    write_be64(ts, timestamp);
    for (i = 0; i < 4; ++i) {
        memcpy(message + i * 8, ts, sizeof(ts));
    }

    HMAC(EVP_md5(), uuid, 16, message, sizeof(message), out, &out_len);
}

static void vmess_make_legacy_iv(uint64_t timestamp, uint8_t out[16]) {
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    uint8_t ts[8];
    int i = 0;

    write_be64(ts, timestamp);
    EVP_DigestInit_ex(md, EVP_md5(), NULL);
    for (i = 0; i < 4; ++i) {
        EVP_DigestUpdate(md, ts, sizeof(ts));
    }
    EVP_DigestFinal_ex(md, out, NULL);
    EVP_MD_CTX_free(md);
}

static int vmess_destination_type(const Destination* destination) {
    switch (destination->type) {
        case DEST_ADDR_IPV4:
            return 0x01;
        case DEST_ADDR_DOMAIN:
            return 0x02;
        case DEST_ADDR_IPV6:
            return 0x03;
        default:
            return 0;
    }
}

static int vmess_encode_destination(const Destination* destination, uint8_t* out, size_t out_size, size_t* out_len) {
    size_t offset = 0;
    int atyp = vmess_destination_type(destination);

    if (atyp == 0 || out_size < 3) {
        return -1;
    }

    write_be16(out + offset, destination->port);
    offset += 2;
    out[offset++] = (uint8_t)atyp;

    if (destination->type == DEST_ADDR_DOMAIN) {
        size_t host_len = strlen(destination->host);
        if (host_len == 0 || host_len > 255 || offset + 1 + host_len > out_size) {
            return -1;
        }
        out[offset++] = (uint8_t)host_len;
        memcpy(out + offset, destination->host, host_len);
        offset += host_len;
    } else {
        if (offset + destination->raw_addr_len > out_size) {
            return -1;
        }
        memcpy(out + offset, destination->raw_addr, destination->raw_addr_len);
        offset += destination->raw_addr_len;
    }

    *out_len = offset;
    return 0;
}

static VMessBodySecurity parse_vmess_security(const EndpointConfig* endpoint) {
    if (_stricmp(endpoint->vmess.security, "aes-128-gcm") == 0 || _stricmp(endpoint->vmess.security, "aes128-gcm") == 0 || _stricmp(endpoint->vmess.security, "auto") == 0 || endpoint->vmess.security[0] == '\0') {
        return VMESS_BODY_AES128_GCM;
    }
    if (_stricmp(endpoint->vmess.security, "chacha20-poly1305") == 0 || _stricmp(endpoint->vmess.security, "chacha20-ietf-poly1305") == 0) {
        return VMESS_BODY_CHACHA20_POLY1305;
    }
    if (_stricmp(endpoint->vmess.security, "none") == 0 || _stricmp(endpoint->vmess.security, "zero") == 0) {
        return VMESS_BODY_NONE;
    }
    return VMESS_BODY_NONE;
}

static uint8_t vmess_security_byte(VMessBodySecurity security) {
    switch (security) {
        case VMESS_BODY_AES128_GCM:
            return VMESS_SEC_AES128_GCM;
        case VMESS_BODY_CHACHA20_POLY1305:
            return VMESS_SEC_CHACHA20_POLY1305;
        case VMESS_BODY_NONE:
        default:
            return VMESS_SEC_NONE;
    }
}

static void vmess_generate_chacha_key(const uint8_t in[16], uint8_t out[32]) {
    MD5(in, 16, out);
    MD5(out, 16, out + 16);
}

static void vmess_generate_chunk_nonce(const uint8_t iv[16], uint32_t count, uint8_t nonce[12]) {
    memcpy(nonce, iv, 12);
    nonce[0] = (uint8_t)((count >> 8) & 0xff);
    nonce[1] = (uint8_t)(count & 0xff);
}

static int vmess_aead_encrypt(const EVP_CIPHER* cipher_type, const uint8_t* key, const uint8_t* nonce, size_t nonce_len,
    const uint8_t* plaintext, size_t plaintext_len, uint8_t* out, size_t* out_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int written = 0;
    int final_written = 0;

    if (ctx == NULL) {
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, cipher_type, NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce_len, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
        EVP_EncryptUpdate(ctx, out, &written, plaintext, (int)plaintext_len) != 1 ||
        EVP_EncryptFinal_ex(ctx, out + written, &final_written) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, VMESS_AEAD_TAG_SIZE, out + written + final_written) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    *out_len = (size_t)(written + final_written + VMESS_AEAD_TAG_SIZE);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

static int vmess_aead_decrypt(const EVP_CIPHER* cipher_type, const uint8_t* key, const uint8_t* nonce, size_t nonce_len,
    const uint8_t* ciphertext, size_t ciphertext_len, uint8_t* out, size_t* out_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int written = 0;
    int final_written = 0;
    size_t data_len = 0;

    if (ctx == NULL || ciphertext_len < VMESS_AEAD_TAG_SIZE) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    data_len = ciphertext_len - VMESS_AEAD_TAG_SIZE;
    if (EVP_DecryptInit_ex(ctx, cipher_type, NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce_len, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
        EVP_DecryptUpdate(ctx, out, &written, ciphertext, (int)data_len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, VMESS_AEAD_TAG_SIZE, (void*)(ciphertext + data_len)) != 1 ||
        EVP_DecryptFinal_ex(ctx, out + written, &final_written) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    *out_len = (size_t)(written + final_written);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

static int vmess_init_session(const EndpointConfig* endpoint, VMessSession* session) {
    memset(session, 0, sizeof(*session));
    session->security = parse_vmess_security(endpoint);

    if (RAND_bytes(session->request_body_key, sizeof(session->request_body_key)) != 1 ||
        RAND_bytes(session->request_body_iv, sizeof(session->request_body_iv)) != 1 ||
        RAND_bytes(&session->response_header, 1) != 1) {
        return -1;
    }

    MD5(session->request_body_key, sizeof(session->request_body_key), session->response_body_key);
    MD5(session->request_body_iv, sizeof(session->request_body_iv), session->response_body_iv);
    return 0;
}

static int vmess_build_legacy_header(const EndpointConfig* endpoint, const ProxySession* proxy_session, const VMessSession* session,
    uint8_t** out, size_t* out_len) {
    uint8_t uuid[16];
    uint8_t cmd_key[16];
    uint8_t auth[16];
    uint8_t iv[16];
    uint8_t plain[512];
    uint8_t dest[300];
    size_t plain_len = 0;
    size_t dest_len = 0;
    uint8_t* final_buf = NULL;
    uint64_t timestamp = (uint64_t)time(NULL);
    EVP_CIPHER_CTX* ctx = NULL;
    int written = 0;
    int final_written = 0;

    if (uuid_to_bytes(endpoint->vmess.uuid, uuid) != 0) {
        return -1;
    }

    if (endpoint->vmess.alter_id == 0) {
        fprintf(stderr, "VMess endpoint %s is using legacy header mode; AEAD-only servers may reject it.\n", endpoint->key);
    }

    vmess_make_cmd_key(uuid, cmd_key);
    vmess_make_legacy_auth(uuid, auth, timestamp);
    vmess_make_legacy_iv(timestamp, iv);

    plain[plain_len++] = VMESS_VERSION;
    memcpy(plain + plain_len, session->request_body_iv, 16);
    plain_len += 16;
    memcpy(plain + plain_len, session->request_body_key, 16);
    plain_len += 16;
    plain[plain_len++] = session->response_header;
    plain[plain_len++] = VMESS_OPT_CHUNK_STREAM;
    plain[plain_len++] = vmess_security_byte(session->security);
    plain[plain_len++] = 0x00;
    plain[plain_len++] = VMESS_CMD_TCP;

    if (vmess_encode_destination(&proxy_session->destination, dest, sizeof(dest), &dest_len) != 0) {
        return -1;
    }
    memcpy(plain + plain_len, dest, dest_len);
    plain_len += dest_len;

    {
        uint32_t checksum = fnv1a32(plain, plain_len);
        plain[plain_len++] = (uint8_t)((checksum >> 24) & 0xff);
        plain[plain_len++] = (uint8_t)((checksum >> 16) & 0xff);
        plain[plain_len++] = (uint8_t)((checksum >> 8) & 0xff);
        plain[plain_len++] = (uint8_t)(checksum & 0xff);
    }

    final_buf = (uint8_t*)malloc(sizeof(auth) + plain_len);
    if (final_buf == NULL) {
        return -1;
    }

    memcpy(final_buf, auth, sizeof(auth));
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL ||
        EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb128(), NULL, cmd_key, iv) != 1 ||
        EVP_CIPHER_CTX_set_padding(ctx, 0) != 1 ||
        EVP_EncryptUpdate(ctx, final_buf + sizeof(auth), &written, plain, (int)plain_len) != 1 ||
        EVP_EncryptFinal_ex(ctx, final_buf + sizeof(auth) + written, &final_written) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(final_buf);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    *out = final_buf;
    *out_len = sizeof(auth) + (size_t)(written + final_written);
    return 0;
}

static int vmess_open_stream(RemoteStream* stream, const EndpointConfig* endpoint) {
    const char* tls_host = endpoint->vmess.servername[0] != '\0' ? endpoint->vmess.servername : endpoint->server;
    const char* ws_path = endpoint->vmess.ws.path[0] != '\0' ? endpoint->vmess.ws.path : "/";
    const char* ws_host = endpoint->vmess.ws.host[0] != '\0' ? endpoint->vmess.ws.host : tls_host;

    if (remote_stream_connect(stream, endpoint->server, endpoint->port) != 0) {
        fprintf(stderr, "Failed to connect to VMess upstream %s:%d\n", endpoint->server, endpoint->port);
        return -1;
    }

    if (endpoint->vmess.tls && remote_stream_enable_tls(stream, tls_host, endpoint->skip_cert_verify) != 0) {
        fprintf(stderr, "VMess TLS handshake failed.\n");
        remote_stream_close(stream);
        return -1;
    }

    if (_stricmp(endpoint->vmess.network, "ws") == 0 &&
        remote_stream_start_websocket(stream, ws_path, ws_host) != 0) {
        fprintf(stderr, "VMess WebSocket handshake failed.\n");
        remote_stream_close(stream);
        return -1;
    }

    return 0;
}

static int vmess_send_chunk(RemoteStream* stream, VMessSession* session, const uint8_t* data, size_t data_len) {
    uint8_t size_buf[2];

    if (session->security == VMESS_BODY_NONE) {
        write_be16(size_buf, (uint16_t)data_len);
        if (remote_stream_send(stream, size_buf, sizeof(size_buf)) != 0) {
            return -1;
        }
        return remote_stream_send(stream, data, data_len);
    }

    {
        uint8_t nonce[12];
        uint8_t encrypted[VMESS_MAX_PLAIN_CHUNK + VMESS_AEAD_TAG_SIZE];
        uint8_t chacha_key[32];
        size_t encrypted_len = 0;

        if (data_len > VMESS_MAX_PLAIN_CHUNK) {
            return -1;
        }

        vmess_generate_chunk_nonce(session->request_body_iv, session->request_chunk_count++, nonce);
        if (session->security == VMESS_BODY_AES128_GCM) {
            if (vmess_aead_encrypt(EVP_aes_128_gcm(), session->request_body_key, nonce, sizeof(nonce), data, data_len, encrypted, &encrypted_len) != 0) {
                return -1;
            }
        } else {
            vmess_generate_chacha_key(session->request_body_key, chacha_key);
            if (vmess_aead_encrypt(EVP_chacha20_poly1305(), chacha_key, nonce, sizeof(nonce), data, data_len, encrypted, &encrypted_len) != 0) {
                return -1;
            }
        }

        write_be16(size_buf, (uint16_t)encrypted_len);
        if (remote_stream_send(stream, size_buf, sizeof(size_buf)) != 0 ||
            remote_stream_send(stream, encrypted, encrypted_len) != 0) {
            return -1;
        }
    }

    return 0;
}

static int vmess_send_buffer(RemoteStream* stream, VMessSession* session, const uint8_t* data, size_t data_len) {
    size_t offset = 0;

    while (offset < data_len) {
        size_t chunk_len = data_len - offset;
        if (chunk_len > VMESS_MAX_PLAIN_CHUNK) {
            chunk_len = VMESS_MAX_PLAIN_CHUNK;
        }
        if (vmess_send_chunk(stream, session, data + offset, chunk_len) != 0) {
            return -1;
        }
        offset += chunk_len;
    }

    return 0;
}

static int vmess_expect_legacy_response(RemoteStream* stream, const VMessSession* session) {
    uint8_t encrypted[4];
    uint8_t decrypted[4];
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int written = 0;
    int final_written = 0;

    if (ctx == NULL || remote_stream_recv_exact(stream, encrypted, sizeof(encrypted)) != 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb128(), NULL, session->response_body_key, session->response_body_iv) != 1 ||
        EVP_CIPHER_CTX_set_padding(ctx, 0) != 1 ||
        EVP_DecryptUpdate(ctx, decrypted, &written, encrypted, sizeof(encrypted)) != 1 ||
        EVP_DecryptFinal_ex(ctx, decrypted + written, &final_written) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (decrypted[0] != session->response_header) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (decrypted[2] != 0 && decrypted[3] > 0) {
        uint8_t extra[256];
        if (decrypted[3] > sizeof(extra) || remote_stream_recv_exact(stream, extra, decrypted[3]) != 0) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        if (EVP_DecryptUpdate(ctx, extra, &written, extra, decrypted[3]) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

static int vmess_recv_chunk(RemoteStream* stream, VMessSession* session, uint8_t* out, size_t out_capacity, size_t* out_len) {
    uint8_t size_buf[2];
    uint16_t size = 0;

    if (remote_stream_recv_exact(stream, size_buf, sizeof(size_buf)) != 0) {
        return -1;
    }

    size = (uint16_t)(((uint16_t)size_buf[0] << 8) | (uint16_t)size_buf[1]);
    if (size == 0) {
        *out_len = 0;
        return 0;
    }

    if (session->security == VMESS_BODY_NONE) {
        if (size > out_capacity || remote_stream_recv_exact(stream, out, size) != 0) {
            return -1;
        }
        *out_len = size;
        return 0;
    }

    {
        uint8_t encrypted[VMESS_MAX_PLAIN_CHUNK + VMESS_AEAD_TAG_SIZE];
        uint8_t nonce[12];
        uint8_t chacha_key[32];
        size_t plain_len = 0;

        if (size > sizeof(encrypted) || size > out_capacity + VMESS_AEAD_TAG_SIZE) {
            return -1;
        }

        if (remote_stream_recv_exact(stream, encrypted, size) != 0) {
            return -1;
        }

        vmess_generate_chunk_nonce(session->response_body_iv, session->response_chunk_count++, nonce);
        if (session->security == VMESS_BODY_AES128_GCM) {
            if (vmess_aead_decrypt(EVP_aes_128_gcm(), session->response_body_key, nonce, sizeof(nonce), encrypted, size, out, &plain_len) != 0) {
                return -1;
            }
        } else {
            vmess_generate_chacha_key(session->response_body_key, chacha_key);
            if (vmess_aead_decrypt(EVP_chacha20_poly1305(), chacha_key, nonce, sizeof(nonce), encrypted, size, out, &plain_len) != 0) {
                return -1;
            }
        }

        *out_len = plain_len;
    }

    return 0;
}

int proxy_vmess_client(SOCKET client_socket, const EndpointConfig* endpoint, const ProxySession* session) {
    RemoteStream remote_stream;
    VMessSession vmess_session;
    uint8_t* header = NULL;
    size_t header_len = 0;
    uint8_t buffer[PULSE_IO_BUFFER_SIZE];
    int response_ready = 0;

    if (_stricmp(endpoint->vmess.network, "tcp") != 0 && _stricmp(endpoint->vmess.network, "ws") != 0) {
        fprintf(stderr, "VMess network %s is not supported in this build.\n", endpoint->vmess.network);
        return report_vmess_failure(client_socket, session);
    }

    if (vmess_init_session(endpoint, &vmess_session) != 0 ||
        vmess_build_legacy_header(endpoint, session, &vmess_session, &header, &header_len) != 0) {
        free(header);
        return report_vmess_failure(client_socket, session);
    }

    if (vmess_open_stream(&remote_stream, endpoint) != 0) {
        free(header);
        return report_vmess_failure(client_socket, session);
    }

    if (remote_stream_send(&remote_stream, header, header_len) != 0) {
        free(header);
        remote_stream_close(&remote_stream);
        return report_vmess_failure(client_socket, session);
    }
    free(header);

    if (session->initial_data_len > 0 && vmess_send_buffer(&remote_stream, &vmess_session, session->initial_data, session->initial_data_len) != 0) {
        remote_stream_close(&remote_stream);
        return report_vmess_failure(client_socket, session);
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
                break;
            }
            if (vmess_send_buffer(&remote_stream, &vmess_session, buffer, (size_t)received) != 0) {
                break;
            }
        }

        if (remote_ready) {
            size_t plain_len = 0;

            if (!response_ready) {
                if (vmess_expect_legacy_response(&remote_stream, &vmess_session) != 0) {
                    break;
                }
                response_ready = 1;
                if (!remote_stream_has_pending_data(&remote_stream)) {
                    continue;
                }
            }

            if (vmess_recv_chunk(&remote_stream, &vmess_session, buffer, sizeof(buffer), &plain_len) != 0) {
                break;
            }

            if (plain_len == 0) {
                continue;
            }

            if (send_all_socket(client_socket, buffer, plain_len) != 0) {
                break;
            }
        }
    }

    remote_stream_shutdown(&remote_stream);
    remote_stream_close(&remote_stream);
    return 0;
}
