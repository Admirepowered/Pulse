#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include "core/proxy.h"
#include "outbounds/stream.h"
#include "outbounds/protocol_helpers.h"

#define SS_TAG_SIZE 16
#define SS_MAX_CHUNK_PAYLOAD 0x3FFF

typedef enum {
    SS_CIPHER_UNKNOWN = 0,
    SS_CIPHER_AES_128_GCM,
    SS_CIPHER_AES_256_GCM,
    SS_CIPHER_CHACHA20_IETF_POLY1305
} ShadowsocksCipherKind;

typedef struct {
    ShadowsocksCipherKind kind;
    size_t key_len;
    size_t salt_len;
} ShadowsocksCipherSpec;

typedef struct {
    EVP_CIPHER_CTX* encrypt_ctx;
    EVP_CIPHER_CTX* decrypt_ctx;
    uint8_t encrypt_nonce[12];
    uint8_t decrypt_nonce[12];
    int initialized;
} ShadowsocksSessionCipher;

static int report_shadowsocks_failure(SOCKET client_socket, const ProxySession* session) {
    if (session->handshake_type == CLIENT_HANDSHAKE_SOCKS5) {
        send_socks_reply(client_socket, 0x05);
    } else if (session->handshake_type == CLIENT_HANDSHAKE_HTTP_CONNECT) {
        send_http_connect_reply(client_socket, 502);
    } else {
        send_http_forward_error(client_socket, 502, "Bad Gateway");
    }
    return -1;
}

static const EVP_CIPHER* get_shadowsocks_evp_cipher(ShadowsocksCipherKind kind) {
    switch (kind) {
        case SS_CIPHER_AES_128_GCM:
            return EVP_aes_128_gcm();
        case SS_CIPHER_AES_256_GCM:
            return EVP_aes_256_gcm();
        case SS_CIPHER_CHACHA20_IETF_POLY1305:
            return EVP_chacha20_poly1305();
        default:
            return NULL;
    }
}

static int get_shadowsocks_cipher_spec(const char* method, ShadowsocksCipherSpec* spec) {
    memset(spec, 0, sizeof(*spec));

    if (_stricmp(method, "aes-128-gcm") == 0 || _stricmp(method, "aead_aes_128_gcm") == 0) {
        spec->kind = SS_CIPHER_AES_128_GCM;
        spec->key_len = 16;
        spec->salt_len = 16;
        return 0;
    }

    if (_stricmp(method, "aes-256-gcm") == 0 || _stricmp(method, "aead_aes_256_gcm") == 0) {
        spec->kind = SS_CIPHER_AES_256_GCM;
        spec->key_len = 32;
        spec->salt_len = 32;
        return 0;
    }

    if (_stricmp(method, "chacha20-ietf-poly1305") == 0 ||
        _stricmp(method, "chacha20-poly1305") == 0 ||
        _stricmp(method, "aead_chacha20_poly1305") == 0) {
        spec->kind = SS_CIPHER_CHACHA20_IETF_POLY1305;
        spec->key_len = 32;
        spec->salt_len = 32;
        return 0;
    }

    return -1;
}

static void increment_shadowsocks_nonce(uint8_t nonce[12]) {
    size_t i = 0;

    for (i = 0; i < 12; ++i) {
        nonce[i] = (uint8_t)(nonce[i] + 1);
        if (nonce[i] != 0) {
            break;
        }
    }
}

static void derive_shadowsocks_master_key(const char* password, uint8_t* out_key, size_t key_len) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    EVP_MD_CTX* md = NULL;
    size_t produced = 0;
    int has_prev = 0;

    md = EVP_MD_CTX_new();
    if (md == NULL) {
        return;
    }

    while (produced < key_len) {
        if (EVP_DigestInit_ex(md, EVP_md5(), NULL) != 1) {
            break;
        }
        if (has_prev) {
            EVP_DigestUpdate(md, digest, sizeof(digest));
        }
        EVP_DigestUpdate(md, password, strlen(password));
        EVP_DigestFinal_ex(md, digest, NULL);

        {
            size_t copy_len = key_len - produced;
            if (copy_len > sizeof(digest)) {
                copy_len = sizeof(digest);
            }
            memcpy(out_key + produced, digest, copy_len);
            produced += copy_len;
        }

        has_prev = 1;
    }

    EVP_MD_CTX_free(md);
}

static int derive_shadowsocks_subkey(const uint8_t* master_key, size_t master_key_len, const uint8_t* salt, size_t salt_len, uint8_t* out_key, size_t out_len) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    static const char info[] = "ss-subkey";

    if (pctx == NULL) {
        return -1;
    }

    if (EVP_PKEY_derive_init(pctx) != 1 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha1()) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)salt_len) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, master_key, (int)master_key_len) != 1 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)(sizeof(info) - 1)) != 1 ||
        EVP_PKEY_derive(pctx, out_key, &out_len) != 1) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    EVP_PKEY_CTX_free(pctx);
    return 0;
}

static int shadowsocks_cipher_init(ShadowsocksSessionCipher* cipher, const ShadowsocksCipherSpec* spec, const uint8_t* key, int encrypt) {
    const EVP_CIPHER* evp_cipher = get_shadowsocks_evp_cipher(spec->kind);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL || evp_cipher == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_CipherInit_ex(ctx, evp_cipher, NULL, NULL, NULL, encrypt) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1 ||
        EVP_CipherInit_ex(ctx, NULL, NULL, key, encrypt ? cipher->encrypt_nonce : cipher->decrypt_nonce, encrypt) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (encrypt) {
        cipher->encrypt_ctx = ctx;
    } else {
        cipher->decrypt_ctx = ctx;
    }

    return 0;
}

static int shadowsocks_encrypt_record(ShadowsocksSessionCipher* cipher, const uint8_t* plaintext, size_t plaintext_len, uint8_t* out, size_t* out_len) {
    int written = 0;
    int final_written = 0;

    if (EVP_EncryptInit_ex(cipher->encrypt_ctx, NULL, NULL, NULL, cipher->encrypt_nonce) != 1 ||
        EVP_EncryptUpdate(cipher->encrypt_ctx, out, &written, plaintext, (int)plaintext_len) != 1 ||
        EVP_EncryptFinal_ex(cipher->encrypt_ctx, out + written, &final_written) != 1 ||
        EVP_CIPHER_CTX_ctrl(cipher->encrypt_ctx, EVP_CTRL_AEAD_GET_TAG, SS_TAG_SIZE, out + written + final_written) != 1) {
        return -1;
    }

    *out_len = (size_t)(written + final_written + SS_TAG_SIZE);
    increment_shadowsocks_nonce(cipher->encrypt_nonce);
    return 0;
}

static int shadowsocks_decrypt_record(ShadowsocksSessionCipher* cipher, const uint8_t* ciphertext, size_t ciphertext_len, uint8_t* out, size_t* out_len) {
    int written = 0;
    int final_written = 0;
    size_t data_len = 0;

    if (ciphertext_len < SS_TAG_SIZE) {
        return -1;
    }

    data_len = ciphertext_len - SS_TAG_SIZE;
    if (EVP_DecryptInit_ex(cipher->decrypt_ctx, NULL, NULL, NULL, cipher->decrypt_nonce) != 1 ||
        EVP_DecryptUpdate(cipher->decrypt_ctx, out, &written, ciphertext, (int)data_len) != 1 ||
        EVP_CIPHER_CTX_ctrl(cipher->decrypt_ctx, EVP_CTRL_AEAD_SET_TAG, SS_TAG_SIZE, (void*)(ciphertext + data_len)) != 1 ||
        EVP_DecryptFinal_ex(cipher->decrypt_ctx, out + written, &final_written) != 1) {
        return -1;
    }

    *out_len = (size_t)(written + final_written);
    increment_shadowsocks_nonce(cipher->decrypt_nonce);
    return 0;
}

static void shadowsocks_cipher_close(ShadowsocksSessionCipher* cipher) {
    if (cipher->encrypt_ctx != NULL) {
        EVP_CIPHER_CTX_free(cipher->encrypt_ctx);
        cipher->encrypt_ctx = NULL;
    }
    if (cipher->decrypt_ctx != NULL) {
        EVP_CIPHER_CTX_free(cipher->decrypt_ctx);
        cipher->decrypt_ctx = NULL;
    }
    memset(cipher->encrypt_nonce, 0, sizeof(cipher->encrypt_nonce));
    memset(cipher->decrypt_nonce, 0, sizeof(cipher->decrypt_nonce));
    cipher->initialized = 0;
}

static int shadowsocks_send_chunk(RemoteStream* remote_stream, ShadowsocksSessionCipher* cipher, const uint8_t* payload, size_t payload_len) {
    uint8_t len_plain[2];
    uint8_t len_cipher[2 + SS_TAG_SIZE];
    uint8_t data_cipher[SS_MAX_CHUNK_PAYLOAD + SS_TAG_SIZE];
    size_t len_cipher_len = 0;
    size_t data_cipher_len = 0;

    len_plain[0] = (uint8_t)((payload_len >> 8) & 0x3f);
    len_plain[1] = (uint8_t)(payload_len & 0xff);

    if (shadowsocks_encrypt_record(cipher, len_plain, sizeof(len_plain), len_cipher, &len_cipher_len) != 0 ||
        shadowsocks_encrypt_record(cipher, payload, payload_len, data_cipher, &data_cipher_len) != 0) {
        return -1;
    }

    if (remote_stream_send(remote_stream, len_cipher, len_cipher_len) != 0 ||
        remote_stream_send(remote_stream, data_cipher, data_cipher_len) != 0) {
        return -1;
    }

    return 0;
}

static int shadowsocks_send_buffer(RemoteStream* remote_stream, ShadowsocksSessionCipher* cipher, const uint8_t* payload, size_t payload_len) {
    size_t offset = 0;

    while (offset < payload_len) {
        size_t chunk_len = payload_len - offset;
        if (chunk_len > SS_MAX_CHUNK_PAYLOAD) {
            chunk_len = SS_MAX_CHUNK_PAYLOAD;
        }

        if (shadowsocks_send_chunk(remote_stream, cipher, payload + offset, chunk_len) != 0) {
            return -1;
        }

        offset += chunk_len;
    }

    return 0;
}

static int shadowsocks_recv_chunk(RemoteStream* remote_stream, ShadowsocksSessionCipher* cipher, uint8_t* out, size_t out_capacity, size_t* out_len) {
    uint8_t len_cipher[2 + SS_TAG_SIZE];
    uint8_t len_plain[2];
    uint8_t data_cipher[SS_MAX_CHUNK_PAYLOAD + SS_TAG_SIZE];
    size_t len_plain_len = 0;
    size_t data_plain_len = 0;
    uint16_t chunk_len = 0;

    if (remote_stream_recv_exact(remote_stream, len_cipher, sizeof(len_cipher)) != 0) {
        return -1;
    }

    if (shadowsocks_decrypt_record(cipher, len_cipher, sizeof(len_cipher), len_plain, &len_plain_len) != 0 || len_plain_len != 2) {
        return -1;
    }

    chunk_len = (uint16_t)(((uint16_t)(len_plain[0] & 0x3f) << 8) | (uint16_t)len_plain[1]);
    if (chunk_len == 0 || chunk_len > SS_MAX_CHUNK_PAYLOAD || chunk_len > out_capacity) {
        return -1;
    }

    if (remote_stream_recv_exact(remote_stream, data_cipher, (size_t)chunk_len + SS_TAG_SIZE) != 0) {
        return -1;
    }

    if (shadowsocks_decrypt_record(cipher, data_cipher, (size_t)chunk_len + SS_TAG_SIZE, out, &data_plain_len) != 0 || data_plain_len != chunk_len) {
        return -1;
    }

    *out_len = data_plain_len;
    return 0;
}

static int open_shadowsocks_stream(RemoteStream* remote_stream, const EndpointConfig* endpoint, const ShadowsocksCipherSpec* spec, ShadowsocksSessionCipher* cipher) {
    uint8_t master_key[32];
    uint8_t salt[32];
    uint8_t subkey[32];

    memset(cipher, 0, sizeof(*cipher));

    if (remote_stream_connect(remote_stream, endpoint->server, endpoint->port) != 0) {
        fprintf(stderr, "Failed to connect to Shadowsocks upstream %s:%d\n", endpoint->server, endpoint->port);
        return -1;
    }

    derive_shadowsocks_master_key(endpoint->shadowsocks.password, master_key, spec->key_len);

    if (RAND_bytes(salt, (int)spec->salt_len) != 1) {
        remote_stream_close(remote_stream);
        return -1;
    }

    if (derive_shadowsocks_subkey(master_key, spec->key_len, salt, spec->salt_len, subkey, spec->key_len) != 0 ||
        shadowsocks_cipher_init(cipher, spec, subkey, 1) != 0) {
        remote_stream_close(remote_stream);
        return -1;
    }

    if (remote_stream_send(remote_stream, salt, spec->salt_len) != 0) {
        shadowsocks_cipher_close(cipher);
        remote_stream_close(remote_stream);
        return -1;
    }

    cipher->initialized = 1;
    return 0;
}

static int ensure_shadowsocks_decrypt_ready(RemoteStream* remote_stream, const ShadowsocksCipherSpec* spec, const EndpointConfig* endpoint, ShadowsocksSessionCipher* cipher) {
    uint8_t master_key[32];
    uint8_t salt[32];
    uint8_t subkey[32];

    if (cipher->decrypt_ctx != NULL) {
        return 0;
    }

    if (remote_stream_recv_exact(remote_stream, salt, spec->salt_len) != 0) {
        return -1;
    }

    derive_shadowsocks_master_key(endpoint->shadowsocks.password, master_key, spec->key_len);
    if (derive_shadowsocks_subkey(master_key, spec->key_len, salt, spec->salt_len, subkey, spec->key_len) != 0 ||
        shadowsocks_cipher_init(cipher, spec, subkey, 0) != 0) {
        return -1;
    }

    return 0;
}

int proxy_shadowsocks_client(SOCKET client_socket, const EndpointConfig* endpoint, const ProxySession* session) {
    RemoteStream remote_stream;
    ShadowsocksCipherSpec spec;
    ShadowsocksSessionCipher cipher;
    uint8_t request_prefix[512 + MAX_INITIAL_DATA_LEN];
    uint8_t buffer[PULSE_IO_BUFFER_SIZE];
    size_t request_prefix_len = 0;
    size_t addr_len = 0;

    if (endpoint->shadowsocks.plugin[0] != '\0') {
        fprintf(stderr, "Shadowsocks plugin mode is not implemented yet.\n");
        return report_shadowsocks_failure(client_socket, session);
    }

    if (get_shadowsocks_cipher_spec(endpoint->shadowsocks.method, &spec) != 0) {
        fprintf(stderr, "Unsupported Shadowsocks method: %s\n", endpoint->shadowsocks.method);
        return report_shadowsocks_failure(client_socket, session);
    }

    if (open_shadowsocks_stream(&remote_stream, endpoint, &spec, &cipher) != 0) {
        return report_shadowsocks_failure(client_socket, session);
    }

    if (encode_destination_streamaddr(&session->destination, request_prefix, sizeof(request_prefix), &addr_len) != 0) {
        shadowsocks_cipher_close(&cipher);
        remote_stream_close(&remote_stream);
        return report_shadowsocks_failure(client_socket, session);
    }
    request_prefix_len = addr_len;

    if (session->initial_data_len > 0) {
        if (request_prefix_len + session->initial_data_len > sizeof(request_prefix)) {
            shadowsocks_cipher_close(&cipher);
            remote_stream_close(&remote_stream);
            return report_shadowsocks_failure(client_socket, session);
        }
        memcpy(request_prefix + request_prefix_len, session->initial_data, session->initial_data_len);
        request_prefix_len += session->initial_data_len;
    }

    if (shadowsocks_send_buffer(&remote_stream, &cipher, request_prefix, request_prefix_len) != 0) {
        shadowsocks_cipher_close(&cipher);
        remote_stream_close(&remote_stream);
        return report_shadowsocks_failure(client_socket, session);
    }

    if (session->handshake_type == CLIENT_HANDSHAKE_SOCKS5) {
        if (send_socks_reply(client_socket, 0x00) != 0) {
            shadowsocks_cipher_close(&cipher);
            remote_stream_close(&remote_stream);
            return -1;
        }
    } else if (session->handshake_type == CLIENT_HANDSHAKE_HTTP_CONNECT) {
        if (send_http_connect_reply(client_socket, 200) != 0) {
            shadowsocks_cipher_close(&cipher);
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

            if (shadowsocks_send_buffer(&remote_stream, &cipher, buffer, (size_t)received) != 0) {
                break;
            }
        }

        if (remote_ready) {
            size_t decrypted_len = 0;

            if (ensure_shadowsocks_decrypt_ready(&remote_stream, &spec, endpoint, &cipher) != 0) {
                break;
            }

            if (shadowsocks_recv_chunk(&remote_stream, &cipher, buffer, sizeof(buffer), &decrypted_len) != 0) {
                break;
            }

            if (send_all_socket(client_socket, buffer, decrypted_len) != 0) {
                break;
            }
        }
    }

    shadowsocks_cipher_close(&cipher);
    remote_stream_shutdown(&remote_stream);
    remote_stream_close(&remote_stream);
    return 0;
}
