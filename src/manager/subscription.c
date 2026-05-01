#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "core/proxy.h"

#if !PLATFORM_IS_WINDOWS
#include <sys/stat.h>
#endif

#define SUB_HTTP_BUFFER 8192
#define SUB_MAX_BODY (1024 * 1024 * 4)
#define SUB_MAX_ENTRIES 256

typedef struct {
    char scheme[16];
    char host[CONFIG_VALUE_LEN];
    int port;
    char path[CONFIG_VALUE_LEN];
    int use_tls;
} ParsedUrl;

typedef struct {
    char host[CONFIG_VALUE_LEN];
    int port;
} ProxyAddress;

typedef struct {
    char key[ENDPOINT_NAME_LEN];
    EndpointConfig endpoint;
} SubscriptionEntry;

static void sub_safe_copy(char* dest, size_t dest_size, const char* src) {
    size_t copy_len = 0;

    if (dest_size == 0) {
        return;
    }

    if (src == NULL) {
        dest[0] = '\0';
        return;
    }

    copy_len = strlen(src);
    if (copy_len >= dest_size) {
        copy_len = dest_size - 1;
    }

    memcpy(dest, src, copy_len);
    dest[copy_len] = '\0';
}

static void trim_inplace(char* text) {
    char* start = text;
    size_t len = 0;

    while (*start != '\0' && isspace((unsigned char)*start)) {
        ++start;
    }

    if (start != text) {
        memmove(text, start, strlen(start) + 1);
    }

    len = strlen(text);
    while (len > 0 && isspace((unsigned char)text[len - 1])) {
        text[len - 1] = '\0';
        --len;
    }
}

static int parse_port(const char* text, int* out) {
    char* end = NULL;
    long value = strtol(text, &end, 10);

    if (end == text || *end != '\0' || value <= 0 || value > 65535) {
        return -1;
    }

    *out = (int)value;
    return 0;
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

static int parse_url(const char* url, ParsedUrl* parsed) {
    const char* scheme_end = strstr(url, "://");
    const char* host_start = NULL;
    const char* path_start = NULL;
    const char* colon = NULL;
    size_t scheme_len = 0;
    size_t host_len = 0;

    memset(parsed, 0, sizeof(*parsed));

    if (scheme_end == NULL) {
        return -1;
    }

    scheme_len = (size_t)(scheme_end - url);
    if (scheme_len == 0 || scheme_len >= sizeof(parsed->scheme)) {
        return -1;
    }

    memcpy(parsed->scheme, url, scheme_len);
    parsed->scheme[scheme_len] = '\0';

    if (_stricmp(parsed->scheme, "https") == 0) {
        parsed->use_tls = 1;
        parsed->port = 443;
    } else if (_stricmp(parsed->scheme, "http") == 0) {
        parsed->use_tls = 0;
        parsed->port = 80;
    } else {
        return -1;
    }

    host_start = scheme_end + 3;
    path_start = strchr(host_start, '/');
    colon = strchr(host_start, ':');

    if (path_start == NULL) {
        path_start = url + strlen(url);
        strcpy(parsed->path, "/");
    } else {
        sub_safe_copy(parsed->path, sizeof(parsed->path), path_start);
    }

    if (colon != NULL && colon < path_start) {
        char port_text[16];
        host_len = (size_t)(colon - host_start);
        if (host_len == 0 || host_len >= sizeof(parsed->host)) {
            return -1;
        }
        memcpy(parsed->host, host_start, host_len);
        parsed->host[host_len] = '\0';

        host_len = (size_t)(path_start - colon - 1);
        if (host_len == 0 || host_len >= sizeof(port_text)) {
            return -1;
        }
        memcpy(port_text, colon + 1, host_len);
        port_text[host_len] = '\0';
        if (parse_port(port_text, &parsed->port) != 0) {
            return -1;
        }
        return 0;
    }

    host_len = (size_t)(path_start - host_start);
    if (host_len == 0 || host_len >= sizeof(parsed->host)) {
        return -1;
    }
    memcpy(parsed->host, host_start, host_len);
    parsed->host[host_len] = '\0';
    return 0;
}

static SOCKET connect_tcp_host(const char* host, int port) {
    struct addrinfo hints;
    struct addrinfo* result = NULL;
    struct addrinfo* item = NULL;
    char port_text[16];
    SOCKET socket_fd = INVALID_SOCKET;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    snprintf(port_text, sizeof(port_text), "%d", port);
    if (getaddrinfo(host, port_text, &hints, &result) != 0) {
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

static int recv_until(SOCKET socket_fd, char* buffer, size_t buffer_size, size_t* out_len, const char* marker) {
    size_t marker_len = strlen(marker);
    size_t total = 0;

    while (total + 1 < buffer_size) {
        int received = recv(socket_fd, buffer + total, (int)(buffer_size - total - 1), 0);
        if (received <= 0) {
            return -1;
        }
        total += (size_t)received;
        buffer[total] = '\0';
        if (total >= marker_len && strstr(buffer, marker) != NULL) {
            *out_len = total;
            return 0;
        }
    }

    return -1;
}

static int parse_http_status(const char* response) {
    const char* space = strchr(response, ' ');
    if (space == NULL) {
        return -1;
    }
    return atoi(space + 1);
}

static int parse_content_length(const char* headers) {
    const char* line = headers;

    while (*line != '\0') {
        const char* end = strstr(line, "\r\n");
        if (end == NULL || end == line) {
            break;
        }

        if (starts_with_ci(line, "Content-Length:")) {
            return atoi(line + 15);
        }

        line = end + 2;
    }

    return -1;
}

static int contains_text_ci(const char* text, size_t text_len, const char* token) {
    size_t token_len = strlen(token);
    size_t i = 0;
    size_t j = 0;

    if (token_len == 0 || text_len < token_len) {
        return 0;
    }

    for (i = 0; i + token_len <= text_len; ++i) {
        for (j = 0; j < token_len; ++j) {
            if (tolower((unsigned char)text[i + j]) != tolower((unsigned char)token[j])) {
                break;
            }
        }
        if (j == token_len) {
            return 1;
        }
    }

    return 0;
}

static int http_is_chunked(const char* headers) {
    const char* line = headers;

    while (*line != '\0') {
        const char* end = strstr(line, "\r\n");
        if (end == NULL || end == line) {
            break;
        }

        if (starts_with_ci(line, "Transfer-Encoding:") &&
            contains_text_ci(line, (size_t)(end - line), "chunked")) {
            return 1;
        }

        line = end + 2;
    }

    return 0;
}

static int decode_chunked_body(const char* encoded_body, size_t encoded_len, char** out_body) {
    const char* cursor = encoded_body;
    const char* end = encoded_body + encoded_len;
    char* decoded = NULL;
    size_t total = 0;

    *out_body = NULL;

    decoded = (char*)malloc(SUB_MAX_BODY + 1);
    if (decoded == NULL) {
        return -1;
    }

    while (cursor < end) {
        const char* line_end = strstr(cursor, "\r\n");
        const char* size_end = NULL;
        unsigned long chunk_size = 0;
        char size_text[32];
        size_t size_len = 0;

        if (line_end == NULL) {
            free(decoded);
            return -1;
        }

        size_end = cursor;
        while (size_end < line_end && *size_end != ';') {
            ++size_end;
        }

        size_len = (size_t)(size_end - cursor);
        if (size_len == 0 || size_len >= sizeof(size_text)) {
            free(decoded);
            return -1;
        }

        memcpy(size_text, cursor, size_len);
        size_text[size_len] = '\0';
        chunk_size = strtoul(size_text, NULL, 16);

        cursor = line_end + 2;

        if (chunk_size == 0) {
            decoded[total] = '\0';
            *out_body = decoded;
            return 0;
        }

        if (chunk_size > (unsigned long)(end - cursor) ||
            total + (size_t)chunk_size > SUB_MAX_BODY) {
            free(decoded);
            return -1;
        }

        memcpy(decoded + total, cursor, (size_t)chunk_size);
        total += (size_t)chunk_size;
        cursor += chunk_size;

        if (cursor + 2 > end || cursor[0] != '\r' || cursor[1] != '\n') {
            free(decoded);
            return -1;
        }
        cursor += 2;
    }

    free(decoded);
    return -1;
}

static int socks5_connect(SOCKET socket_fd, const char* host, int port) {
    uint8_t greeting[] = {0x05, 0x01, 0x00};
    uint8_t response[2];
    uint8_t request[4 + 1 + 255 + 2];
    size_t host_len = strlen(host);

    if (host_len == 0 || host_len > 255) {
        return -1;
    }

    if (send_all_socket(socket_fd, greeting, sizeof(greeting)) != 0 ||
        recv_exact_socket(socket_fd, response, sizeof(response)) != 0) {
        return -1;
    }
    if (response[0] != 0x05 || response[1] != 0x00) {
        return -1;
    }

    request[0] = 0x05;
    request[1] = 0x01;
    request[2] = 0x00;
    request[3] = 0x03;
    request[4] = (uint8_t)host_len;
    memcpy(request + 5, host, host_len);
    request[5 + host_len] = (uint8_t)((port >> 8) & 0xFF);
    request[6 + host_len] = (uint8_t)(port & 0xFF);

    if (send_all_socket(socket_fd, request, 7 + host_len) != 0) {
        return -1;
    }

    if (recv_exact_socket(socket_fd, response, 2) != 0) {
        return -1;
    }
    if (response[0] != 0x05 || response[1] != 0x00) {
        return -1;
    }

    {
        uint8_t head[2];
        if (recv_exact_socket(socket_fd, head, sizeof(head)) != 0) {
            return -1;
        }
        if (head[1] == 0x01) {
            uint8_t skip[4 + 2];
            if (recv_exact_socket(socket_fd, skip, sizeof(skip)) != 0) {
                return -1;
            }
        } else if (head[1] == 0x03) {
            uint8_t len = 0;
            uint8_t skip[257];
            if (recv_exact_socket(socket_fd, &len, 1) != 0) {
                return -1;
            }
            if (recv_exact_socket(socket_fd, skip, (size_t)len + 2) != 0) {
                return -1;
            }
        } else if (head[1] == 0x04) {
            uint8_t skip[16 + 2];
            if (recv_exact_socket(socket_fd, skip, sizeof(skip)) != 0) {
                return -1;
            }
        } else {
            return -1;
        }
    }

    return 0;
}

static int enable_tls_client(SSL_CTX** out_ctx, SSL** out_ssl, SOCKET socket_fd, const char* host) {
    SSL_CTX* ctx = NULL;
    SSL* ssl = NULL;

    *out_ctx = NULL;
    *out_ssl = NULL;

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        return -1;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        SSL_CTX_free(ctx);
        return -1;
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        SSL_CTX_free(ctx);
        return -1;
    }

    if (SSL_set_fd(ssl, (int)socket_fd) != 1 ||
        SSL_set_tlsext_host_name(ssl, host) != 1 ||
        SSL_set1_host(ssl, host) != 1 ||
        SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return -1;
    }

    *out_ctx = ctx;
    *out_ssl = ssl;
    return 0;
}

static int ssl_send_all(SSL* ssl, const uint8_t* data, size_t len) {
    size_t total = 0;

    while (total < len) {
        int sent = SSL_write(ssl, data + total, (int)(len - total));
        if (sent <= 0) {
            return -1;
        }
        total += (size_t)sent;
    }

    return 0;
}

static int ssl_recv_into(SSL* ssl, char* buffer, size_t buffer_size, size_t* out_len) {
    size_t total = 0;

    while (total + 1 < buffer_size) {
        int received = SSL_read(ssl, buffer + total, (int)(buffer_size - total - 1));
        if (received <= 0) {
            break;
        }
        total += (size_t)received;
    }

    buffer[total] = '\0';
    *out_len = total;
    return total > 0 ? 0 : -1;
}

static int parse_proxy_spec(const char* proxy_spec, ProxyAddress* proxy) {
    const char* colon = NULL;
    char port_text[16];
    size_t host_len = 0;

    if (proxy_spec == NULL) {
        return 1;
    }

    if (proxy_spec[0] == '\0') {
        strcpy(proxy->host, "127.0.0.1");
        proxy->port = 1080;
        return 0;
    }

    if (_stricmp(proxy_spec, "direct") == 0) {
        return 1;
    }

    colon = strrchr(proxy_spec, ':');
    if (colon == NULL) {
        return -1;
    }

    host_len = (size_t)(colon - proxy_spec);
    if (host_len == 0 || host_len >= sizeof(proxy->host)) {
        return -1;
    }
    memcpy(proxy->host, proxy_spec, host_len);
    proxy->host[host_len] = '\0';

    sub_safe_copy(port_text, sizeof(port_text), colon + 1);
    return parse_port(port_text, &proxy->port);
}

static int http_download_body(const char* url, const char* proxy_spec, char** out_body) {
    ParsedUrl parsed;
    ProxyAddress proxy;
    SOCKET socket_fd = INVALID_SOCKET;
    SSL_CTX* ssl_ctx = NULL;
    SSL* ssl = NULL;
    char request[2048];
    char* response = NULL;
    char* decoded_chunked = NULL;
    size_t response_len = 0;
    size_t body_len = 0;
    char* header_end = NULL;
    char* body = NULL;
    int content_length = -1;
    int chunked = 0;
    int status = 0;
    int result = -1;

    *out_body = NULL;

    if (parse_url(url, &parsed) != 0) {
        fprintf(stderr, "Unsupported subscription URL: %s\n", url);
        return -1;
    }

    if (parse_proxy_spec(proxy_spec, &proxy) == 0) {
        socket_fd = connect_tcp_host(proxy.host, proxy.port);
        if (socket_fd == INVALID_SOCKET) {
            fprintf(stderr, "Failed to connect proxy %s:%d\n", proxy.host, proxy.port);
            return -1;
        }
        if (socks5_connect(socket_fd, parsed.host, parsed.port) != 0) {
            fprintf(stderr, "SOCKS5 connect failed.\n");
            goto cleanup;
        }
    } else if (proxy_spec != NULL) {
        fprintf(stderr, "Invalid proxy spec: %s\n", proxy_spec);
        return -1;
    } else {
        socket_fd = connect_tcp_host(parsed.host, parsed.port);
        if (socket_fd == INVALID_SOCKET) {
            fprintf(stderr, "Failed to connect %s:%d\n", parsed.host, parsed.port);
            return -1;
        }
    }

    if (parsed.use_tls) {
        if (enable_tls_client(&ssl_ctx, &ssl, socket_fd, parsed.host) != 0) {
            fprintf(stderr, "TLS handshake failed for %s\n", parsed.host);
            goto cleanup;
        }
    }

    snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Pulse/1.0\r\n"
        "Connection: close\r\n"
        "Accept: */*\r\n"
        "\r\n",
        parsed.path,
        parsed.host);

    if (ssl != NULL) {
        if (ssl_send_all(ssl, (const uint8_t*)request, strlen(request)) != 0) {
            goto cleanup;
        }
        response = (char*)malloc(SUB_MAX_BODY + SUB_HTTP_BUFFER);
        if (response == NULL || ssl_recv_into(ssl, response, SUB_MAX_BODY + SUB_HTTP_BUFFER, &response_len) != 0) {
            goto cleanup;
        }
    } else {
        if (send_all_socket(socket_fd, (const uint8_t*)request, strlen(request)) != 0) {
            goto cleanup;
        }
        response = (char*)malloc(SUB_MAX_BODY + SUB_HTTP_BUFFER);
        if (response == NULL || recv_until(socket_fd, response, SUB_MAX_BODY + SUB_HTTP_BUFFER, &response_len, "\r\n\r\n") != 0) {
            goto cleanup;
        }
        while (response_len + 1 < SUB_MAX_BODY + SUB_HTTP_BUFFER) {
            int received = recv(socket_fd, response + response_len, (int)(SUB_MAX_BODY + SUB_HTTP_BUFFER - response_len - 1), 0);
            if (received <= 0) {
                break;
            }
            response_len += (size_t)received;
            response[response_len] = '\0';
        }
    }

    header_end = strstr(response, "\r\n\r\n");
    if (header_end == NULL) {
        goto cleanup;
    }

    status = parse_http_status(response);
    if (status < 200 || status >= 300) {
        fprintf(stderr, "Subscription request failed with HTTP %d\n", status);
        goto cleanup;
    }

    content_length = parse_content_length(response);
    chunked = http_is_chunked(response);
    body = header_end + 4;
    body_len = response_len - (size_t)(body - response);

    if (chunked) {
        if (decode_chunked_body(body, body_len, &decoded_chunked) != 0) {
            fprintf(stderr, "Failed to decode chunked subscription response.\n");
            goto cleanup;
        }
        *out_body = decoded_chunked;
        decoded_chunked = NULL;
        result = 0;
        goto cleanup;
    }

    if (content_length < 0) {
        content_length = (int)body_len;
    }
    if (content_length < 0 || content_length > SUB_MAX_BODY) {
        goto cleanup;
    }

    *out_body = (char*)malloc((size_t)content_length + 1);
    if (*out_body == NULL) {
        goto cleanup;
    }
    memcpy(*out_body, body, (size_t)content_length);
    (*out_body)[content_length] = '\0';
    result = 0;

cleanup:
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ssl_ctx != NULL) {
        SSL_CTX_free(ssl_ctx);
    }
    if (socket_fd != INVALID_SOCKET) {
        shutdown(socket_fd, SD_BOTH);
        closesocket(socket_fd);
    }
    free(response);
    free(decoded_chunked);
    return result;
}

static int contains_subscription_scheme(const char* text) {
    size_t text_len = strlen(text);
    return contains_text_ci(text, text_len, "vless://") ||
        contains_text_ci(text, text_len, "hysteria2://") ||
        contains_text_ci(text, text_len, "hy2://") ||
        contains_text_ci(text, text_len, "trojan://") ||
        contains_text_ci(text, text_len, "ss://") ||
        contains_text_ci(text, text_len, "ssr://") ||
        contains_text_ci(text, text_len, "vmess://") ||
        contains_text_ci(text, text_len, "tuic://") ||
        contains_text_ci(text, text_len, "anytls://");
}

static int normalize_base64_text(const char* input, char** out_normalized) {
    char* normalized = NULL;
    size_t input_len = strlen(input);
    size_t i = 0;
    size_t j = 0;

    *out_normalized = NULL;

    normalized = (char*)malloc(input_len + 5);
    if (normalized == NULL) {
        return -1;
    }

    for (i = 0; i < input_len; ++i) {
        unsigned char ch = (unsigned char)input[i];
        if (isspace(ch)) {
            continue;
        }
        if (isalnum(ch) || ch == '+' || ch == '/' || ch == '=') {
            normalized[j++] = (char)ch;
            continue;
        }
        if (ch == '-') {
            normalized[j++] = '+';
            continue;
        }
        if (ch == '_') {
            normalized[j++] = '/';
            continue;
        }

        free(normalized);
        return -1;
    }

    if (j == 0 || (j % 4) == 1) {
        free(normalized);
        return -1;
    }

    while ((j % 4) != 0) {
        normalized[j++] = '=';
    }

    normalized[j] = '\0';
    *out_normalized = normalized;
    return 0;
}

static int base64_decode_text(const char* input, unsigned char** out_data, size_t* out_len) {
    unsigned char* buffer = NULL;
    char* normalized = NULL;
    size_t normalized_len = 0;
    size_t padding = 0;
    int decoded_len = 0;

    *out_data = NULL;
    *out_len = 0;

    if (normalize_base64_text(input, &normalized) != 0) {
        return -1;
    }

    normalized_len = strlen(normalized);
    buffer = (unsigned char*)malloc(normalized_len + 1);
    if (buffer == NULL) {
        free(normalized);
        return -1;
    }

    if (normalized_len > 0 && normalized[normalized_len - 1] == '=') {
        ++padding;
    }
    if (normalized_len > 1 && normalized[normalized_len - 2] == '=') {
        ++padding;
    }

    decoded_len = EVP_DecodeBlock(buffer, (const unsigned char*)normalized, (int)normalized_len);
    free(normalized);
    if (decoded_len < 0 || (size_t)decoded_len < padding) {
        free(buffer);
        return -1;
    }

    decoded_len -= (int)padding;
    buffer[decoded_len] = '\0';
    *out_data = buffer;
    *out_len = (size_t)decoded_len;
    return 0;
}

static void build_body_preview(const char* text, char* preview, size_t preview_size) {
    size_t i = 0;
    size_t j = 0;

    if (preview_size == 0) {
        return;
    }

    for (i = 0; text[i] != '\0' && j + 1 < preview_size; ++i) {
        unsigned char ch = (unsigned char)text[i];
        if (ch == '\r' || ch == '\n' || ch == '\t') {
            preview[j++] = ' ';
        } else if (isprint(ch)) {
            preview[j++] = (char)ch;
        } else {
            preview[j++] = '.';
        }
    }

    preview[j] = '\0';
}

static void sanitize_key(const char* input, char* out, size_t out_size, int fallback_index) {
    size_t i = 0;
    size_t j = 0;

    for (i = 0; input[i] != '\0' && j + 1 < out_size; ++i) {
        unsigned char ch = (unsigned char)input[i];
        if (isalnum(ch)) {
            out[j++] = (char)tolower(ch);
        } else if (ch == '-' || ch == '_' || ch == '.') {
            out[j++] = '-';
        }
    }

    if (j == 0) {
        snprintf(out, out_size, "node-%d", fallback_index);
        return;
    }

    out[j] = '\0';
}

static int hex_char_to_int(int ch) {
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

static void url_decode_inplace(char* text) {
    char* read = text;
    char* write = text;

    while (*read != '\0') {
        if (*read == '%' && isxdigit((unsigned char)read[1]) && isxdigit((unsigned char)read[2])) {
            int hi = hex_char_to_int(read[1]);
            int lo = hex_char_to_int(read[2]);
            *write++ = (char)((hi << 4) | lo);
            read += 3;
            continue;
        }
        if (*read == '+') {
            *write++ = ' ';
            ++read;
            continue;
        }
        *write++ = *read++;
    }

    *write = '\0';
}

static int split_query_pair(char* item, char** key, char** value) {
    char* eq = strchr(item, '=');
    if (eq == NULL) {
        return -1;
    }
    *eq = '\0';
    *key = item;
    *value = eq + 1;
    url_decode_inplace(*key);
    url_decode_inplace(*value);
    return 0;
}

static int fill_subscription_common(EndpointConfig* endpoint, const char* host_port, const char* fragment, int index) {
    const char* at = strchr(host_port, '@');
    const char* host_start = at != NULL ? at + 1 : host_port;
    const char* colon = strrchr(host_start, ':');
    char server[CONFIG_VALUE_LEN];
    char port_text[16];

    if (colon == NULL) {
        return -1;
    }

    if ((size_t)(colon - host_start) >= sizeof(server) || strlen(colon + 1) >= sizeof(port_text)) {
        return -1;
    }

    memcpy(server, host_start, (size_t)(colon - host_start));
    server[colon - host_start] = '\0';
    sub_safe_copy(port_text, sizeof(port_text), colon + 1);

    endpoint->enabled = true;
    endpoint->port = atoi(port_text);
    if (endpoint->port <= 0 || endpoint->port > 65535) {
        return -1;
    }
    sub_safe_copy(endpoint->server, sizeof(endpoint->server), server);
    sub_safe_copy(endpoint->name, sizeof(endpoint->name), fragment != NULL && fragment[0] != '\0' ? fragment : host_start);
    sanitize_key(endpoint->name, endpoint->key, sizeof(endpoint->key), index);
    return at != NULL ? 0 : -1;
}

static void set_endpoint_defaults(EndpointConfig* endpoint) {
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->enabled = true;
    endpoint->port = 443;
    endpoint->vless.enabled = true;
    endpoint->vless.tls = true;
    strcpy(endpoint->vless.network, "ws");
    strcpy(endpoint->vless.ws.path, "/");
}

static int parse_vless_uri(const char* uri, SubscriptionEntry* entry, int index) {
    const char* body = uri + 8;
    const char* query = strchr(body, '?');
    const char* fragment = strchr(body, '#');
    char authority[CONFIG_VALUE_LEN * 2];
    char query_text[CONFIG_VALUE_LEN * 4];
    char fragment_text[ENDPOINT_LABEL_LEN];
    char userinfo[128];
    char* at = NULL;
    char* amp = NULL;

    set_endpoint_defaults(&entry->endpoint);
    entry->endpoint.type = ENDPOINT_TYPE_VLESS;
    entry->endpoint.vless.enabled = true;

    if (query == NULL) {
        query = uri + strlen(uri);
    }
    if (fragment == NULL) {
        fragment = uri + strlen(uri);
    }

    if (query > fragment) {
        query = fragment;
    }

    if ((size_t)(query - body) >= sizeof(authority)) {
        return -1;
    }
    memcpy(authority, body, (size_t)(query - body));
    authority[query - body] = '\0';

    if (fragment[0] == '#') {
        sub_safe_copy(fragment_text, sizeof(fragment_text), fragment + 1);
        url_decode_inplace(fragment_text);
    } else {
        fragment_text[0] = '\0';
    }

    if (fill_subscription_common(&entry->endpoint, authority, fragment_text, index) != 0) {
        return -1;
    }

    at = strchr(authority, '@');
    if (at == NULL || (size_t)(at - authority) >= sizeof(userinfo)) {
        return -1;
    }
    memcpy(userinfo, authority, (size_t)(at - authority));
    userinfo[at - authority] = '\0';
    sub_safe_copy(entry->endpoint.vless.uuid, sizeof(entry->endpoint.vless.uuid), userinfo);

    if (query[0] == '?') {
        const char* query_end = fragment < uri + strlen(uri) ? fragment : uri + strlen(uri);
        if ((size_t)(query_end - query - 1) >= sizeof(query_text)) {
            return -1;
        }
        memcpy(query_text, query + 1, (size_t)(query_end - query - 1));
        query_text[query_end - query - 1] = '\0';

        amp = query_text;
        while (amp != NULL && *amp != '\0') {
            char* next = strchr(amp, '&');
            char* key = NULL;
            char* value = NULL;
            if (next != NULL) {
                *next = '\0';
            }
            if (split_query_pair(amp, &key, &value) == 0) {
                if (_stricmp(key, "type") == 0) {
                    sub_safe_copy(entry->endpoint.vless.network, sizeof(entry->endpoint.vless.network), value);
                } else if (_stricmp(key, "security") == 0) {
                    entry->endpoint.vless.tls = _stricmp(value, "tls") == 0;
                } else if (_stricmp(key, "host") == 0) {
                    sub_safe_copy(entry->endpoint.vless.ws.host, sizeof(entry->endpoint.vless.ws.host), value);
                } else if (_stricmp(key, "path") == 0) {
                    sub_safe_copy(entry->endpoint.vless.ws.path, sizeof(entry->endpoint.vless.ws.path), value);
                } else if (_stricmp(key, "sni") == 0 || _stricmp(key, "servername") == 0) {
                    sub_safe_copy(entry->endpoint.vless.servername, sizeof(entry->endpoint.vless.servername), value);
                } else if (_stricmp(key, "fp") == 0) {
                    sub_safe_copy(entry->endpoint.vless.client_fingerprint, sizeof(entry->endpoint.vless.client_fingerprint), value);
                } else if (_stricmp(key, "flow") == 0) {
                    sub_safe_copy(entry->endpoint.vless.flow, sizeof(entry->endpoint.vless.flow), value);
                } else if (_stricmp(key, "allowInsecure") == 0 || _stricmp(key, "insecure") == 0) {
                    entry->endpoint.skip_cert_verify = strcmp(value, "1") == 0 || _stricmp(value, "true") == 0;
                }
            }
            if (next == NULL) {
                break;
            }
            amp = next + 1;
        }
    }

    if (entry->endpoint.vless.servername[0] == '\0') {
        if (entry->endpoint.vless.ws.host[0] != '\0') {
            sub_safe_copy(entry->endpoint.vless.servername, sizeof(entry->endpoint.vless.servername), entry->endpoint.vless.ws.host);
        } else {
            sub_safe_copy(entry->endpoint.vless.servername, sizeof(entry->endpoint.vless.servername), entry->endpoint.server);
        }
    }

    if (entry->endpoint.vless.ws.host[0] == '\0') {
        sub_safe_copy(entry->endpoint.vless.ws.host, sizeof(entry->endpoint.vless.ws.host), entry->endpoint.vless.servername);
    }

    sub_safe_copy(entry->key, sizeof(entry->key), entry->endpoint.key);
    return 0;
}

static int parse_ss_uri(const char* uri, SubscriptionEntry* entry, int index) {
    const char* body = uri + 5;
    const char* fragment = strchr(body, '#');
    const char* query = strchr(body, '?');
    const char* end = uri + strlen(uri);
    char main_part[CONFIG_VALUE_LEN * 4];
    char fragment_text[ENDPOINT_LABEL_LEN];
    char decoded[CONFIG_VALUE_LEN * 4];
    unsigned char* decoded_bytes = NULL;
    size_t decoded_len = 0;
    char credentials_host[CONFIG_VALUE_LEN * 4];
    char* at = NULL;
    char* colon = NULL;
    char* method = NULL;
    char* password = NULL;

    set_endpoint_defaults(&entry->endpoint);
    entry->endpoint.type = ENDPOINT_TYPE_SHADOWSOCKS;
    entry->endpoint.vless.enabled = false;
    entry->endpoint.shadowsocks.enabled = true;

    if (query == NULL) {
        query = end;
    }
    if (fragment == NULL) {
        fragment = end;
    }

    if (query > fragment) {
        query = fragment;
    }

    if ((size_t)(query - body) >= sizeof(main_part)) {
        return -1;
    }
    memcpy(main_part, body, (size_t)(query - body));
    main_part[query - body] = '\0';

    if (fragment[0] == '#') {
        sub_safe_copy(fragment_text, sizeof(fragment_text), fragment + 1);
        url_decode_inplace(fragment_text);
    } else {
        fragment_text[0] = '\0';
    }

    if (strchr(main_part, '@') == NULL) {
        if (base64_decode_text(main_part, &decoded_bytes, &decoded_len) != 0 || decoded_len >= sizeof(decoded)) {
            free(decoded_bytes);
            return -1;
        }
        memcpy(decoded, decoded_bytes, decoded_len);
        decoded[decoded_len] = '\0';
        free(decoded_bytes);
        sub_safe_copy(credentials_host, sizeof(credentials_host), decoded);
    } else {
        char userinfo_b64[CONFIG_VALUE_LEN * 2];
        const char* host_part = strchr(main_part, '@');
        size_t userinfo_len = (size_t)(host_part - main_part);

        if (userinfo_len >= sizeof(userinfo_b64)) {
            return -1;
        }
        memcpy(userinfo_b64, main_part, userinfo_len);
        userinfo_b64[userinfo_len] = '\0';
        if (base64_decode_text(userinfo_b64, &decoded_bytes, &decoded_len) != 0 || decoded_len + strlen(host_part) >= sizeof(credentials_host)) {
            free(decoded_bytes);
            return -1;
        }
        memcpy(credentials_host, decoded_bytes, decoded_len);
        credentials_host[decoded_len] = '\0';
        strcat(credentials_host, host_part);
        free(decoded_bytes);
    }

    if (fill_subscription_common(&entry->endpoint, credentials_host, fragment_text, index) != 0) {
        return -1;
    }

    at = strchr(credentials_host, '@');
    if (at == NULL) {
        return -1;
    }
    *at = '\0';
    colon = strchr(credentials_host, ':');
    if (colon == NULL) {
        return -1;
    }
    *colon = '\0';
    method = credentials_host;
    password = colon + 1;

    sub_safe_copy(entry->endpoint.shadowsocks.method, sizeof(entry->endpoint.shadowsocks.method), method);
    sub_safe_copy(entry->endpoint.shadowsocks.password, sizeof(entry->endpoint.shadowsocks.password), password);
    sub_safe_copy(entry->key, sizeof(entry->key), entry->endpoint.key);
    return 0;
}

static int parse_hysteria2_uri(const char* uri, SubscriptionEntry* entry, int index) {
    const char* body = uri + 12;
    const char* query = strchr(body, '?');
    const char* fragment = strchr(body, '#');
    char authority[CONFIG_VALUE_LEN * 2];
    char fragment_text[ENDPOINT_LABEL_LEN];
    char password[128];
    char* at = NULL;
    char* amp = NULL;
    char query_text[CONFIG_VALUE_LEN * 4];

    set_endpoint_defaults(&entry->endpoint);
    entry->endpoint.type = ENDPOINT_TYPE_HYSTERIA2;
    entry->endpoint.vless.enabled = false;
    entry->endpoint.hysteria2.enabled = true;

    if (query == NULL) {
        query = uri + strlen(uri);
    }
    if (fragment == NULL) {
        fragment = uri + strlen(uri);
    }
    if (query > fragment) {
        query = fragment;
    }

    if ((size_t)(query - body) >= sizeof(authority)) {
        return -1;
    }
    memcpy(authority, body, (size_t)(query - body));
    authority[query - body] = '\0';

    if (fragment[0] == '#') {
        sub_safe_copy(fragment_text, sizeof(fragment_text), fragment + 1);
        url_decode_inplace(fragment_text);
    } else {
        fragment_text[0] = '\0';
    }

    if (fill_subscription_common(&entry->endpoint, authority, fragment_text, index) != 0) {
        return -1;
    }

    at = strchr(authority, '@');
    if (at == NULL || (size_t)(at - authority) >= sizeof(password)) {
        return -1;
    }
    memcpy(password, authority, (size_t)(at - authority));
    password[at - authority] = '\0';
    sub_safe_copy(entry->endpoint.hysteria2.password, sizeof(entry->endpoint.hysteria2.password), password);

    if (query[0] == '?') {
        const char* query_end = fragment < uri + strlen(uri) ? fragment : uri + strlen(uri);
        if ((size_t)(query_end - query - 1) >= sizeof(query_text)) {
            return -1;
        }
        memcpy(query_text, query + 1, (size_t)(query_end - query - 1));
        query_text[query_end - query - 1] = '\0';

        amp = query_text;
        while (amp != NULL && *amp != '\0') {
            char* next = strchr(amp, '&');
            char* key = NULL;
            char* value = NULL;
            if (next != NULL) {
                *next = '\0';
            }
            if (split_query_pair(amp, &key, &value) == 0) {
                if (_stricmp(key, "sni") == 0) {
                    sub_safe_copy(entry->endpoint.hysteria2.sni, sizeof(entry->endpoint.hysteria2.sni), value);
                } else if (_stricmp(key, "insecure") == 0) {
                    entry->endpoint.skip_cert_verify = strcmp(value, "1") == 0 || _stricmp(value, "true") == 0;
                }
            }
            if (next == NULL) {
                break;
            }
            amp = next + 1;
        }
    }

    if (entry->endpoint.hysteria2.sni[0] == '\0') {
        sub_safe_copy(entry->endpoint.hysteria2.sni, sizeof(entry->endpoint.hysteria2.sni), entry->endpoint.server);
    }

    sub_safe_copy(entry->key, sizeof(entry->key), entry->endpoint.key);
    return 0;
}

static int parse_vmess_uri(const char* uri, SubscriptionEntry* entry, int index) {
    const char* body = uri + 8;
    unsigned char* decoded_bytes = NULL;
    size_t decoded_len = 0;
    char json_text[CONFIG_VALUE_LEN * 8];
    char fragment_text[ENDPOINT_LABEL_LEN];
    char* field = NULL;

    set_endpoint_defaults(&entry->endpoint);
    entry->endpoint.type = ENDPOINT_TYPE_VMESS;
    entry->endpoint.vless.enabled = false;
    entry->endpoint.vmess.enabled = true;
    entry->endpoint.vmess.tls = true;
    strcpy(entry->endpoint.vmess.network, "ws");
    strcpy(entry->endpoint.vmess.security, "auto");

    if (base64_decode_text(body, &decoded_bytes, &decoded_len) != 0 || decoded_len >= sizeof(json_text)) {
        free(decoded_bytes);
        return -1;
    }

    memcpy(json_text, decoded_bytes, decoded_len);
    json_text[decoded_len] = '\0';
    free(decoded_bytes);

    field = strstr(json_text, "\"ps\"");
    if (field != NULL) {
        char* start = strchr(field + 4, '"');
        char* end = start != NULL ? strchr(start + 1, '"') : NULL;
        if (start != NULL && end != NULL && (size_t)(end - start - 1) < sizeof(fragment_text)) {
            memcpy(fragment_text, start + 1, (size_t)(end - start - 1));
            fragment_text[end - start - 1] = '\0';
        } else {
            fragment_text[0] = '\0';
        }
    } else {
        fragment_text[0] = '\0';
    }

    {
        char* add = strstr(json_text, "\"add\"");
        char* port = strstr(json_text, "\"port\"");
        char* id = strstr(json_text, "\"id\"");
        if (add == NULL || port == NULL || id == NULL) {
            return -1;
        }

        {
            char* s = strchr(add + 5, '"');
            char* e = s != NULL ? strchr(s + 1, '"') : NULL;
            if (s == NULL || e == NULL || (size_t)(e - s - 1) >= sizeof(entry->endpoint.server)) {
                return -1;
            }
            memcpy(entry->endpoint.server, s + 1, (size_t)(e - s - 1));
            entry->endpoint.server[e - s - 1] = '\0';
        }

        {
            char* colon = strchr(port, ':');
            if (colon == NULL) {
                return -1;
            }
            entry->endpoint.port = atoi(colon + 1);
            if (entry->endpoint.port <= 0 || entry->endpoint.port > 65535) {
                return -1;
            }
        }

        {
            char* s = strchr(id + 4, '"');
            char* e = s != NULL ? strchr(s + 1, '"') : NULL;
            if (s == NULL || e == NULL || (size_t)(e - s - 1) >= sizeof(entry->endpoint.vmess.uuid)) {
                return -1;
            }
            memcpy(entry->endpoint.vmess.uuid, s + 1, (size_t)(e - s - 1));
            entry->endpoint.vmess.uuid[e - s - 1] = '\0';
        }
    }

    {
        char* aid = strstr(json_text, "\"aid\"");
        char* net = strstr(json_text, "\"net\"");
        char* tls = strstr(json_text, "\"tls\"");
        char* host = strstr(json_text, "\"host\"");
        char* path = strstr(json_text, "\"path\"");
        char* sni = strstr(json_text, "\"sni\"");
        char* scy = strstr(json_text, "\"scy\"");

        if (aid != NULL) {
            char* colon = strchr(aid, ':');
            if (colon != NULL) {
                entry->endpoint.vmess.alter_id = atoi(colon + 1);
            }
        }
        if (net != NULL) {
            char* s = strchr(net + 5, '"');
            char* e = s != NULL ? strchr(s + 1, '"') : NULL;
            if (s != NULL && e != NULL) {
                char tmp[16];
                size_t n = (size_t)(e - s - 1);
                if (n >= sizeof(tmp)) {
                    n = sizeof(tmp) - 1;
                }
                memcpy(tmp, s + 1, n);
                tmp[n] = '\0';
                sub_safe_copy(entry->endpoint.vmess.network, sizeof(entry->endpoint.vmess.network), tmp);
            }
        }
        if (tls != NULL) {
            char* s = strchr(tls + 5, '"');
            char* e = s != NULL ? strchr(s + 1, '"') : NULL;
            if (s != NULL && e != NULL) {
                char tmp[16];
                size_t n = (size_t)(e - s - 1);
                if (n >= sizeof(tmp)) {
                    n = sizeof(tmp) - 1;
                }
                memcpy(tmp, s + 1, n);
                tmp[n] = '\0';
                entry->endpoint.vmess.tls = _stricmp(tmp, "tls") == 0;
            }
        }
        if (host != NULL) {
            char* s = strchr(host + 6, '"');
            char* e = s != NULL ? strchr(s + 1, '"') : NULL;
            if (s != NULL && e != NULL) {
                char tmp[CONFIG_VALUE_LEN];
                size_t n = (size_t)(e - s - 1);
                if (n >= sizeof(tmp)) {
                    n = sizeof(tmp) - 1;
                }
                memcpy(tmp, s + 1, n);
                tmp[n] = '\0';
                sub_safe_copy(entry->endpoint.vmess.ws.host, sizeof(entry->endpoint.vmess.ws.host), tmp);
            }
        }
        if (path != NULL) {
            char* s = strchr(path + 6, '"');
            char* e = s != NULL ? strchr(s + 1, '"') : NULL;
            if (s != NULL && e != NULL) {
                char tmp[CONFIG_VALUE_LEN];
                size_t n = (size_t)(e - s - 1);
                if (n >= sizeof(tmp)) {
                    n = sizeof(tmp) - 1;
                }
                memcpy(tmp, s + 1, n);
                tmp[n] = '\0';
                sub_safe_copy(entry->endpoint.vmess.ws.path, sizeof(entry->endpoint.vmess.ws.path), tmp);
            }
        }
        if (sni != NULL) {
            char* s = strchr(sni + 5, '"');
            char* e = s != NULL ? strchr(s + 1, '"') : NULL;
            if (s != NULL && e != NULL) {
                char tmp[CONFIG_VALUE_LEN];
                size_t n = (size_t)(e - s - 1);
                if (n >= sizeof(tmp)) {
                    n = sizeof(tmp) - 1;
                }
                memcpy(tmp, s + 1, n);
                tmp[n] = '\0';
                sub_safe_copy(entry->endpoint.vmess.servername, sizeof(entry->endpoint.vmess.servername), tmp);
            }
        }
        if (scy != NULL) {
            char* s = strchr(scy + 5, '"');
            char* e = s != NULL ? strchr(s + 1, '"') : NULL;
            if (s != NULL && e != NULL) {
                char tmp[32];
                size_t n = (size_t)(e - s - 1);
                if (n >= sizeof(tmp)) {
                    n = sizeof(tmp) - 1;
                }
                memcpy(tmp, s + 1, n);
                tmp[n] = '\0';
                sub_safe_copy(entry->endpoint.vmess.security, sizeof(entry->endpoint.vmess.security), tmp);
            }
        }
    }

    if (fragment_text[0] != '\0') {
        sub_safe_copy(entry->endpoint.name, sizeof(entry->endpoint.name), fragment_text);
    } else {
        sub_safe_copy(entry->endpoint.name, sizeof(entry->endpoint.name), entry->endpoint.server);
    }
    sanitize_key(entry->endpoint.name, entry->endpoint.key, sizeof(entry->endpoint.key), index);

    if (entry->endpoint.vmess.servername[0] == '\0') {
        if (entry->endpoint.vmess.ws.host[0] != '\0') {
            sub_safe_copy(entry->endpoint.vmess.servername, sizeof(entry->endpoint.vmess.servername), entry->endpoint.vmess.ws.host);
        } else {
            sub_safe_copy(entry->endpoint.vmess.servername, sizeof(entry->endpoint.vmess.servername), entry->endpoint.server);
        }
    }
    if (entry->endpoint.vmess.ws.host[0] == '\0') {
        sub_safe_copy(entry->endpoint.vmess.ws.host, sizeof(entry->endpoint.vmess.ws.host), entry->endpoint.vmess.servername);
    }
    if (entry->endpoint.vmess.ws.path[0] == '\0') {
        strcpy(entry->endpoint.vmess.ws.path, "/");
    }

    sub_safe_copy(entry->key, sizeof(entry->key), entry->endpoint.key);
    return 0;
}

static int parse_trojan_uri(const char* uri, SubscriptionEntry* entry, int index) {
    const char* body = uri + 9;
    const char* query = strchr(body, '?');
    const char* fragment = strchr(body, '#');
    char authority[CONFIG_VALUE_LEN * 2];
    char fragment_text[ENDPOINT_LABEL_LEN];
    char password[128];
    char* at = NULL;
    char* amp = NULL;
    char query_text[CONFIG_VALUE_LEN * 4];

    set_endpoint_defaults(&entry->endpoint);
    entry->endpoint.type = ENDPOINT_TYPE_TROJAN;
    entry->endpoint.vless.enabled = false;
    entry->endpoint.trojan.enabled = true;
    entry->endpoint.trojan.tls = true;
    strcpy(entry->endpoint.trojan.network, "tcp");

    if (query == NULL) {
        query = uri + strlen(uri);
    }
    if (fragment == NULL) {
        fragment = uri + strlen(uri);
    }
    if (query > fragment) {
        query = fragment;
    }

    if ((size_t)(query - body) >= sizeof(authority)) {
        return -1;
    }
    memcpy(authority, body, (size_t)(query - body));
    authority[query - body] = '\0';

    if (fragment[0] == '#') {
        sub_safe_copy(fragment_text, sizeof(fragment_text), fragment + 1);
        url_decode_inplace(fragment_text);
    } else {
        fragment_text[0] = '\0';
    }

    if (fill_subscription_common(&entry->endpoint, authority, fragment_text, index) != 0) {
        return -1;
    }

    at = strchr(authority, '@');
    if (at == NULL || (size_t)(at - authority) >= sizeof(password)) {
        return -1;
    }
    memcpy(password, authority, (size_t)(at - authority));
    password[at - authority] = '\0';
    sub_safe_copy(entry->endpoint.trojan.password, sizeof(entry->endpoint.trojan.password), password);

    if (query[0] == '?') {
        const char* query_end = fragment < uri + strlen(uri) ? fragment : uri + strlen(uri);
        if ((size_t)(query_end - query - 1) >= sizeof(query_text)) {
            return -1;
        }
        memcpy(query_text, query + 1, (size_t)(query_end - query - 1));
        query_text[query_end - query - 1] = '\0';

        amp = query_text;
        while (amp != NULL && *amp != '\0') {
            char* next = strchr(amp, '&');
            char* key = NULL;
            char* value = NULL;
            if (next != NULL) {
                *next = '\0';
            }
            if (split_query_pair(amp, &key, &value) == 0) {
                if (_stricmp(key, "security") == 0) {
                    entry->endpoint.trojan.tls = _stricmp(value, "tls") == 0;
                } else if (_stricmp(key, "host") == 0) {
                    sub_safe_copy(entry->endpoint.trojan.ws.host, sizeof(entry->endpoint.trojan.ws.host), value);
                } else if (_stricmp(key, "path") == 0) {
                    sub_safe_copy(entry->endpoint.trojan.ws.path, sizeof(entry->endpoint.trojan.ws.path), value);
                } else if (_stricmp(key, "type") == 0) {
                    sub_safe_copy(entry->endpoint.trojan.network, sizeof(entry->endpoint.trojan.network), value);
                } else if (_stricmp(key, "sni") == 0 || _stricmp(key, "servername") == 0) {
                    sub_safe_copy(entry->endpoint.trojan.servername, sizeof(entry->endpoint.trojan.servername), value);
                } else if (_stricmp(key, "fp") == 0) {
                    sub_safe_copy(entry->endpoint.trojan.client_fingerprint, sizeof(entry->endpoint.trojan.client_fingerprint), value);
                } else if (_stricmp(key, "allowInsecure") == 0 || _stricmp(key, "insecure") == 0) {
                    entry->endpoint.skip_cert_verify = strcmp(value, "1") == 0 || _stricmp(value, "true") == 0;
                }
            }
            if (next == NULL) {
                break;
            }
            amp = next + 1;
        }
    }

    if (entry->endpoint.trojan.servername[0] == '\0') {
        sub_safe_copy(entry->endpoint.trojan.servername, sizeof(entry->endpoint.trojan.servername), entry->endpoint.server);
    }
    if (entry->endpoint.trojan.ws.host[0] == '\0') {
        sub_safe_copy(entry->endpoint.trojan.ws.host, sizeof(entry->endpoint.trojan.ws.host), entry->endpoint.trojan.servername);
    }

    sub_safe_copy(entry->key, sizeof(entry->key), entry->endpoint.key);
    return 0;
}

static int parse_subscription_line(const char* line, SubscriptionEntry* entry, int index) {
    if (starts_with_ci(line, "ss://")) {
        return parse_ss_uri(line, entry, index);
    }
    if (starts_with_ci(line, "vmess://")) {
        return parse_vmess_uri(line, entry, index);
    }
    if (starts_with_ci(line, "vless://")) {
        return parse_vless_uri(line, entry, index);
    }
    if (starts_with_ci(line, "hysteria2://")) {
        return parse_hysteria2_uri(line, entry, index);
    }
    if (starts_with_ci(line, "hy2://")) {
        char normalized[CONFIG_VALUE_LEN * 4];
        snprintf(normalized, sizeof(normalized), "hysteria2://%s", line + 6);
        return parse_hysteria2_uri(normalized, entry, index);
    }
    if (starts_with_ci(line, "trojan://")) {
        return parse_trojan_uri(line, entry, index);
    }
    return -1;
}

static void extract_domain_name(const char* host, char* out, size_t out_size) {
    size_t i = 0;
    size_t j = 0;

    for (i = 0; host[i] != '\0' && j + 1 < out_size; ++i) {
        unsigned char ch = (unsigned char)host[i];
        if (isalnum(ch)) {
            out[j++] = (char)tolower(ch);
        } else if (ch == '.' || ch == '-') {
            out[j++] = (char)ch;
        }
    }

    if (j == 0) {
        strcpy(out, "subscription");
        return;
    }

    out[j] = '\0';
}

static int ensure_config_dir(void) {
#if PLATFORM_IS_WINDOWS
    if (CreateDirectoryA("config", NULL) != 0 || GetLastError() == ERROR_ALREADY_EXISTS) {
        return 0;
    }
    return -1;
#else
    if (mkdir("config", 0755) == 0 || errno == EEXIST) {
        return 0;
    }
    return -1;
#endif
}

static int write_subscription_toml(const char* output_path, SubscriptionEntry* entries, int count) {
    FILE* fp = fopen(output_path, "wb");
    int i = 0;

    if (fp == NULL) {
        return -1;
    }

    for (i = 0; i < count; ++i) {
        EndpointConfig* endpoint = &entries[i].endpoint;

        fprintf(fp, "[endpoints.%s]\n", entries[i].key);
        fprintf(fp, "name = \"%s\"\n", endpoint->name);
        fprintf(fp, "type = \"%s\"\n", endpoint_type_name(endpoint->type));
        fprintf(fp, "server = \"%s\"\n", endpoint->server);
        fprintf(fp, "port = %d\n", endpoint->port);
        fprintf(fp, "udp = %s\n", endpoint->udp ? "true" : "false");
        fprintf(fp, "skip-cert-verify = %s\n", endpoint->skip_cert_verify ? "true" : "false");

        if (endpoint->type == ENDPOINT_TYPE_VLESS) {
            fprintf(fp, "uuid = \"%s\"\n", endpoint->vless.uuid);
            fprintf(fp, "tls = %s\n", endpoint->vless.tls ? "true" : "false");
            fprintf(fp, "flow = \"%s\"\n", endpoint->vless.flow);
            fprintf(fp, "client-fingerprint = \"%s\"\n", endpoint->vless.client_fingerprint);
            fprintf(fp, "servername = \"%s\"\n", endpoint->vless.servername);
            fprintf(fp, "network = \"%s\"\n\n", endpoint->vless.network);
            fprintf(fp, "[endpoints.%s.ws-opts]\n", entries[i].key);
            fprintf(fp, "path = \"%s\"\n", endpoint->vless.ws.path);
            fprintf(fp, "headers = { Host = \"%s\" }\n\n", endpoint->vless.ws.host);
        } else if (endpoint->type == ENDPOINT_TYPE_SHADOWSOCKS) {
            fprintf(fp, "method = \"%s\"\n", endpoint->shadowsocks.method);
            fprintf(fp, "password = \"%s\"\n", endpoint->shadowsocks.password);
            fprintf(fp, "plugin = \"%s\"\n\n", endpoint->shadowsocks.plugin);
        } else if (endpoint->type == ENDPOINT_TYPE_VMESS) {
            fprintf(fp, "uuid = \"%s\"\n", endpoint->vmess.uuid);
            fprintf(fp, "alter-id = %d\n", endpoint->vmess.alter_id);
            fprintf(fp, "security = \"%s\"\n", endpoint->vmess.security);
            fprintf(fp, "tls = %s\n", endpoint->vmess.tls ? "true" : "false");
            fprintf(fp, "servername = \"%s\"\n", endpoint->vmess.servername);
            fprintf(fp, "network = \"%s\"\n\n", endpoint->vmess.network);
            if (_stricmp(endpoint->vmess.network, "ws") == 0) {
                fprintf(fp, "[endpoints.%s.ws-opts]\n", entries[i].key);
                fprintf(fp, "path = \"%s\"\n", endpoint->vmess.ws.path);
                fprintf(fp, "headers = { Host = \"%s\" }\n\n", endpoint->vmess.ws.host);
            }
        } else if (endpoint->type == ENDPOINT_TYPE_HYSTERIA2) {
            fprintf(fp, "sni = \"%s\"\n", endpoint->hysteria2.sni);
            fprintf(fp, "password = \"%s\"\n\n", endpoint->hysteria2.password);
        } else if (endpoint->type == ENDPOINT_TYPE_TROJAN) {
            fprintf(fp, "password = \"%s\"\n", endpoint->trojan.password);
            fprintf(fp, "tls = %s\n", endpoint->trojan.tls ? "true" : "false");
            fprintf(fp, "servername = \"%s\"\n", endpoint->trojan.servername);
            fprintf(fp, "network = \"%s\"\n", endpoint->trojan.network);
            fprintf(fp, "client-fingerprint = \"%s\"\n\n", endpoint->trojan.client_fingerprint);
            if (_stricmp(endpoint->trojan.network, "ws") == 0) {
                fprintf(fp, "[endpoints.%s.ws-opts]\n", entries[i].key);
                fprintf(fp, "path = \"%s\"\n", endpoint->trojan.ws.path);
                fprintf(fp, "headers = { Host = \"%s\" }\n\n", endpoint->trojan.ws.host);
            }
        }
    }

    fclose(fp);
    return 0;
}

int download_subscription_command(const char* url, const char* proxy_spec) {
    char* response_body = NULL;
    unsigned char* decoded = NULL;
    size_t decoded_len = 0;
    char* lines = NULL;
    char preview[121];
    char file_host[CONFIG_VALUE_LEN];
    char output_name[CONFIG_VALUE_LEN];
    char output_path[CONFIG_PATH_LEN];
    SubscriptionEntry entries[SUB_MAX_ENTRIES];
    int entry_count = 0;
    ParsedUrl parsed;
    char* line = NULL;
    char* next = NULL;
    int result = 1;

    if (http_download_body(url, proxy_spec, &response_body) != 0) {
        return 1;
    }

    trim_inplace(response_body);
    if (contains_subscription_scheme(response_body)) {
        decoded_len = strlen(response_body);
        decoded = (unsigned char*)malloc(decoded_len + 1);
        if (decoded == NULL) {
            fprintf(stderr, "Failed to allocate subscription buffer.\n");
            goto cleanup;
        }
        memcpy(decoded, response_body, decoded_len + 1);
    } else if (base64_decode_text(response_body, &decoded, &decoded_len) != 0) {
        build_body_preview(response_body, preview, sizeof(preview));
        fprintf(stderr,
            "Failed to decode subscription response. body_len=%zu preview=\"%s\"\n",
            strlen(response_body),
            preview);
        goto cleanup;
    }

    lines = (char*)malloc(decoded_len + 1);
    if (lines == NULL) {
        goto cleanup;
    }
    memcpy(lines, decoded, decoded_len);
    lines[decoded_len] = '\0';

    line = lines;
    while (line != NULL && *line != '\0' && entry_count < SUB_MAX_ENTRIES) {
        SubscriptionEntry entry;
        next = strpbrk(line, "\r\n");
        if (next != NULL) {
            *next = '\0';
            while (next[1] == '\r' || next[1] == '\n') {
                ++next;
            }
            ++next;
        }

        trim_inplace(line);
        if (line[0] != '\0') {
            memset(&entry, 0, sizeof(entry));
            if (parse_subscription_line(line, &entry, entry_count + 1) == 0) {
                entries[entry_count++] = entry;
            }
        }

        line = next;
    }

    if (entry_count == 0) {
        fprintf(stderr, "No supported subscription entries were found.\n");
        goto cleanup;
    }

    if (parse_url(url, &parsed) != 0) {
        goto cleanup;
    }

    extract_domain_name(parsed.host, file_host, sizeof(file_host));
    snprintf(output_name, sizeof(output_name), "%s.toml", file_host);
    snprintf(output_path, sizeof(output_path), "config/%s", output_name);

    if (ensure_config_dir() != 0) {
        fprintf(stderr, "Failed to create config directory.\n");
        goto cleanup;
    }

    if (write_subscription_toml(output_path, entries, entry_count) != 0) {
        fprintf(stderr, "Failed to write %s\n", output_path);
        goto cleanup;
    }

    printf("Saved subscription: %s\n", output_path);
    printf("Imported endpoints: %d\n", entry_count);
    printf("Add this to your main config:\n");
    printf("[main]\n");
    printf("include = [\"%s\"]\n", output_name);
    result = 0;

cleanup:
    free(response_body);
    free(decoded);
    free(lines);
    return result;
}

static int read_subscription_file_body(const char* path, char** out_body) {
    FILE* fp = NULL;
    long size = 0;
    char* body = NULL;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open subscription file: %s\n", path);
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    size = ftell(fp);
    if (size < 0 || size > SUB_MAX_BODY) {
        fclose(fp);
        fprintf(stderr, "Subscription file is too large.\n");
        return -1;
    }
    rewind(fp);

    body = (char*)malloc((size_t)size + 1);
    if (body == NULL) {
        fclose(fp);
        return -1;
    }

    if (size > 0 && fread(body, 1, (size_t)size, fp) != (size_t)size) {
        fclose(fp);
        free(body);
        return -1;
    }
    fclose(fp);

    body[size] = '\0';
    *out_body = body;
    return 0;
}

static void sanitize_output_name(const char* input, char* out, size_t out_size) {
    size_t i = 0;
    size_t j = 0;
    const char* start = input;

    if (input == NULL || input[0] == '\0') {
        sub_safe_copy(out, out_size, "imported.toml");
        return;
    }

    for (i = 0; input[i] != '\0'; ++i) {
        if (input[i] == '/' || input[i] == '\\') {
            start = input + i + 1;
        }
    }

    for (i = 0; start[i] != '\0' && j + 1 < out_size; ++i) {
        char c = start[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
            out[j++] = c;
        } else {
            out[j++] = '-';
        }
    }
    out[j] = '\0';

    if (out[0] == '\0') {
        sub_safe_copy(out, out_size, "imported.toml");
    }
    if (strstr(out, ".toml") == NULL) {
        size_t len = strlen(out);
        if (len + 5 < out_size) {
            strcat(out, ".toml");
        }
    }
}

int import_subscription_file_command(const char* input_path, const char* output_name_arg) {
    char* response_body = NULL;
    unsigned char* decoded = NULL;
    size_t decoded_len = 0;
    char* lines = NULL;
    char preview[121];
    char output_name[CONFIG_VALUE_LEN];
    char output_path[CONFIG_PATH_LEN];
    SubscriptionEntry entries[SUB_MAX_ENTRIES];
    int entry_count = 0;
    char* line = NULL;
    char* next = NULL;
    int result = 1;

    if (read_subscription_file_body(input_path, &response_body) != 0) {
        return 1;
    }

    trim_inplace(response_body);
    if (contains_subscription_scheme(response_body)) {
        decoded_len = strlen(response_body);
        decoded = (unsigned char*)malloc(decoded_len + 1);
        if (decoded == NULL) {
            goto cleanup;
        }
        memcpy(decoded, response_body, decoded_len + 1);
    } else if (base64_decode_text(response_body, &decoded, &decoded_len) != 0) {
        build_body_preview(response_body, preview, sizeof(preview));
        fprintf(stderr,
            "Failed to decode subscription file. body_len=%zu preview=\"%s\"\n",
            strlen(response_body),
            preview);
        goto cleanup;
    }

    lines = (char*)malloc(decoded_len + 1);
    if (lines == NULL) {
        goto cleanup;
    }
    memcpy(lines, decoded, decoded_len);
    lines[decoded_len] = '\0';

    line = lines;
    while (line != NULL && *line != '\0' && entry_count < SUB_MAX_ENTRIES) {
        SubscriptionEntry entry;
        next = strpbrk(line, "\r\n");
        if (next != NULL) {
            *next = '\0';
            while (next[1] == '\r' || next[1] == '\n') {
                ++next;
            }
            ++next;
        }

        trim_inplace(line);
        if (line[0] != '\0') {
            memset(&entry, 0, sizeof(entry));
            if (parse_subscription_line(line, &entry, entry_count + 1) == 0) {
                entries[entry_count++] = entry;
            }
        }

        line = next;
    }

    if (entry_count == 0) {
        fprintf(stderr, "No supported subscription entries were found.\n");
        goto cleanup;
    }

    sanitize_output_name(output_name_arg != NULL ? output_name_arg : input_path, output_name, sizeof(output_name));
    snprintf(output_path, sizeof(output_path), "config/%s", output_name);

    if (ensure_config_dir() != 0) {
        fprintf(stderr, "Failed to create config directory.\n");
        goto cleanup;
    }

    if (write_subscription_toml(output_path, entries, entry_count) != 0) {
        fprintf(stderr, "Failed to write %s\n", output_path);
        goto cleanup;
    }

    printf("Saved subscription: %s\n", output_path);
    printf("Imported endpoints: %d\n", entry_count);
    result = 0;

cleanup:
    free(response_body);
    free(decoded);
    free(lines);
    return result;
}
