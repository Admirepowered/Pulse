#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "core/proxy.h"

static int recv_peek_socket(SOCKET socket_fd, uint8_t* data, size_t len) {
    int received = recv(socket_fd, (char*)data, (int)len, MSG_PEEK);
    return received;
}

static int recv_line_socket(SOCKET socket_fd, char* buffer, size_t buffer_size, size_t* out_len) {
    size_t total = 0;

    while (total + 1 < buffer_size) {
        int received = recv(socket_fd, buffer + total, 1, 0);
        if (received <= 0) {
            return -1;
        }
        total += (size_t)received;
        buffer[total] = '\0';
        if (total >= 2 && buffer[total - 2] == '\r' && buffer[total - 1] == '\n') {
            *out_len = total;
            return 0;
        }
    }

    return -1;
}

static void trim_trailing_line_endings(char* text) {
    size_t len = strlen(text);

    while (len > 0 && (text[len - 1] == '\r' || text[len - 1] == '\n')) {
        text[len - 1] = '\0';
        --len;
    }
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

static int parse_http_url_destination(const char* url, Destination* destination) {
    const char* scheme_end = strstr(url, "://");
    const char* host_start = NULL;
    const char* host_end = NULL;
    const char* path_start = NULL;
    const char* colon = NULL;
    char port_text[16];
    int default_port = 80;

    if (scheme_end == NULL) {
        return -1;
    }

    if (_strnicmp(url, "https://", 8) == 0) {
        default_port = 443;
    } else if (_strnicmp(url, "http://", 7) != 0) {
        return -1;
    }

    host_start = scheme_end + 3;
    path_start = strchr(host_start, '/');
    if (path_start == NULL) {
        path_start = url + strlen(url);
    }
    host_end = path_start;

    colon = strrchr(host_start, ':');
    if (colon != NULL && colon < path_start) {
        size_t host_len = (size_t)(colon - host_start);
        size_t port_len = (size_t)(path_start - colon - 1);
        if (host_len == 0 || host_len >= sizeof(destination->host) || port_len == 0 || port_len >= sizeof(port_text)) {
            return -1;
        }
        memcpy(destination->host, host_start, host_len);
        destination->host[host_len] = '\0';
        memcpy(port_text, colon + 1, port_len);
        port_text[port_len] = '\0';
        destination->port = (uint16_t)atoi(port_text);
    } else {
        size_t host_len = (size_t)(host_end - host_start);
        if (host_len == 0 || host_len >= sizeof(destination->host)) {
            return -1;
        }
        memcpy(destination->host, host_start, host_len);
        destination->host[host_len] = '\0';
        destination->port = (uint16_t)default_port;
    }

    destination->type = DEST_ADDR_DOMAIN;
    return destination->port == 0 ? -1 : 0;
}

static int parse_host_port_destination(const char* host_port, uint16_t default_port, Destination* destination) {
    const char* colon = strrchr(host_port, ':');
    char port_text[16];
    size_t host_len = 0;

    memset(destination, 0, sizeof(*destination));

    if (colon == NULL) {
        host_len = strlen(host_port);
        if (host_len == 0 || host_len >= sizeof(destination->host)) {
            return -1;
        }
        memcpy(destination->host, host_port, host_len);
        destination->host[host_len] = '\0';
        destination->port = default_port;
    } else {
        host_len = (size_t)(colon - host_port);
        if (host_len == 0 || host_len >= sizeof(destination->host) || strlen(colon + 1) >= sizeof(port_text)) {
            return -1;
        }
        memcpy(destination->host, host_port, host_len);
        destination->host[host_len] = '\0';
        strcpy(port_text, colon + 1);
        destination->port = (uint16_t)atoi(port_text);
    }

    destination->type = DEST_ADDR_DOMAIN;
    return destination->port == 0 ? -1 : 0;
}

static int receive_http_headers(SOCKET client_socket, uint8_t* initial_data, size_t initial_capacity, size_t* out_len, char first_line[1024], char host_header[512]) {
    char line[2048];
    size_t line_len = 0;
    size_t total = 0;
    int saw_first_line = 0;

    first_line[0] = '\0';
    host_header[0] = '\0';

    for (;;) {
        if (recv_line_socket(client_socket, line, sizeof(line), &line_len) != 0) {
            return -1;
        }

        if (total + line_len > initial_capacity) {
            return -1;
        }

        memcpy(initial_data + total, line, line_len);
        total += line_len;

        trim_trailing_line_endings(line);
        if (!saw_first_line) {
            strncpy(first_line, line, 1023);
            first_line[1023] = '\0';
            saw_first_line = 1;
        } else if (starts_with_ci(line, "Host:")) {
            const char* value = line + 5;
            while (*value != '\0' && isspace((unsigned char)*value)) {
                ++value;
            }
            strncpy(host_header, value, 511);
            host_header[511] = '\0';
        }

        if (line[0] == '\0') {
            *out_len = total;
            return 0;
        }
    }
}

int send_all_socket(SOCKET socket_fd, const uint8_t* data, size_t len) {
    size_t sent_total = 0;

    while (sent_total < len) {
        int sent = send(socket_fd, (const char*)data + sent_total, (int)(len - sent_total), 0);
        if (sent == SOCKET_ERROR || sent == 0) {
            return -1;
        }
        sent_total += (size_t)sent;
    }

    return 0;
}

int recv_exact_socket(SOCKET socket_fd, uint8_t* data, size_t len) {
    size_t received_total = 0;

    while (received_total < len) {
        int received = recv(socket_fd, (char*)data + received_total, (int)(len - received_total), 0);
        if (received <= 0) {
            return -1;
        }
        received_total += (size_t)received;
    }

    return 0;
}

void format_destination(const Destination* destination, char* out, size_t out_size) {
    if (destination->type == DEST_ADDR_DOMAIN) {
        snprintf(out, out_size, "%s:%u", destination->host, (unsigned int)destination->port);
        return;
    }

    if (destination->type == DEST_ADDR_IPV4) {
        char addr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, destination->raw_addr, addr, sizeof(addr));
        snprintf(out, out_size, "%s:%u", addr, (unsigned int)destination->port);
        return;
    }

    if (destination->type == DEST_ADDR_IPV6) {
        char addr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, destination->raw_addr, addr, sizeof(addr));
        snprintf(out, out_size, "[%s]:%u", addr, (unsigned int)destination->port);
        return;
    }

    snprintf(out, out_size, "unknown:%u", (unsigned int)destination->port);
}

int send_socks_reply(SOCKET client_socket, uint8_t reply_code) {
    uint8_t response[] = {0x05, reply_code, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    return send_all_socket(client_socket, response, sizeof(response));
}

int send_http_connect_reply(SOCKET client_socket, int status_code) {
    char response[256];
    const char* reason = status_code == 200 ? "Connection Established" :
        status_code == 400 ? "Bad Request" :
        status_code == 403 ? "Forbidden" :
        status_code == 502 ? "Bad Gateway" : "Error";

    snprintf(response, sizeof(response),
        "HTTP/1.1 %d %s\r\n"
        "Proxy-Agent: Pulse/1.0\r\n"
        "\r\n",
        status_code, reason);
    return send_all_socket(client_socket, (const uint8_t*)response, strlen(response));
}

int send_http_forward_error(SOCKET client_socket, int status_code, const char* reason) {
    char response[512];

    snprintf(response, sizeof(response),
        "HTTP/1.1 %d %s\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n"
        "Proxy-Agent: Pulse/1.0\r\n"
        "\r\n",
        status_code, reason != NULL ? reason : "Error");
    return send_all_socket(client_socket, (const uint8_t*)response, strlen(response));
}

static int handle_socks5_handshake(SOCKET client_socket, ProxySession* session) {
    uint8_t header[4];
    uint8_t methods_len[2];
    uint8_t reply[2] = {0x05, 0x00};
    uint8_t port_bytes[2];
    Destination* destination = &session->destination;

    if (recv_exact_socket(client_socket, methods_len, sizeof(methods_len)) != 0) {
        return -1;
    }

    if (methods_len[0] != 0x05) {
        return -1;
    }

    if (methods_len[1] > 0) {
        uint8_t methods[255];
        if (recv_exact_socket(client_socket, methods, methods_len[1]) != 0) {
            return -1;
        }
    }

    if (send_all_socket(client_socket, reply, sizeof(reply)) != 0) {
        return -1;
    }

    if (recv_exact_socket(client_socket, header, sizeof(header)) != 0) {
        return -1;
    }

    if (header[0] != 0x05) {
        return -1;
    }

    if (header[1] != 0x01) {
        send_socks_reply(client_socket, 0x07);
        return -1;
    }

    memset(destination, 0, sizeof(*destination));

    switch (header[3]) {
        case 0x01:
            destination->type = DEST_ADDR_IPV4;
            destination->raw_addr_len = 4;
            if (recv_exact_socket(client_socket, destination->raw_addr, destination->raw_addr_len) != 0) {
                return -1;
            }
            break;
        case 0x03: {
            uint8_t domain_len = 0;
            destination->type = DEST_ADDR_DOMAIN;
            if (recv_exact_socket(client_socket, &domain_len, 1) != 0) {
                return -1;
            }
            if (domain_len == 0) {
                send_socks_reply(client_socket, 0x08);
                return -1;
            }
            if (recv_exact_socket(client_socket, (uint8_t*)destination->host, domain_len) != 0) {
                return -1;
            }
            destination->host[domain_len] = '\0';
            break;
        }
        case 0x04:
            destination->type = DEST_ADDR_IPV6;
            destination->raw_addr_len = 16;
            if (recv_exact_socket(client_socket, destination->raw_addr, destination->raw_addr_len) != 0) {
                return -1;
            }
            break;
        default:
            send_socks_reply(client_socket, 0x08);
            return -1;
    }

    if (recv_exact_socket(client_socket, port_bytes, sizeof(port_bytes)) != 0) {
        return -1;
    }

    destination->port = (uint16_t)(((uint16_t)port_bytes[0] << 8) | (uint16_t)port_bytes[1]);
    session->handshake_type = CLIENT_HANDSHAKE_SOCKS5;
    session->initial_data_len = 0;
    return 0;
}

static int handle_http_handshake(SOCKET client_socket, ProxySession* session) {
    char first_line[1024];
    char host_header[512];
    char method[32];
    char target[768];
    char version[32];

    memset(session, 0, sizeof(*session));

    if (receive_http_headers(client_socket, session->initial_data, sizeof(session->initial_data), &session->initial_data_len, first_line, host_header) != 0) {
        return -1;
    }

    if (sscanf(first_line, "%31s %767s %31s", method, target, version) != 3) {
        send_http_forward_error(client_socket, 400, "Bad Request");
        return -1;
    }

    if (_stricmp(method, "CONNECT") == 0) {
        if (parse_host_port_destination(target, 443, &session->destination) != 0) {
            send_http_connect_reply(client_socket, 400);
            return -1;
        }
        session->handshake_type = CLIENT_HANDSHAKE_HTTP_CONNECT;
        session->initial_data_len = 0;
        return 0;
    }

    if (parse_http_url_destination(target, &session->destination) != 0) {
        if (host_header[0] == '\0' || parse_host_port_destination(host_header, 80, &session->destination) != 0) {
            send_http_forward_error(client_socket, 400, "Bad Request");
            return -1;
        }
    }

    session->handshake_type = CLIENT_HANDSHAKE_HTTP_FORWARD;
    return 0;
}

int detect_and_handle_inbound(SOCKET client_socket, InboundType configured_type, ProxySession* session) {
    uint8_t first_bytes[8];
    int peeked = 0;

    memset(session, 0, sizeof(*session));

    if (configured_type == INBOUND_TYPE_SOCKS5) {
        return handle_socks5_handshake(client_socket, session);
    }
    if (configured_type == INBOUND_TYPE_HTTP) {
        return handle_http_handshake(client_socket, session);
    }

    peeked = recv_peek_socket(client_socket, first_bytes, sizeof(first_bytes));
    if (peeked <= 0) {
        return -1;
    }

    if (first_bytes[0] == 0x05) {
        return handle_socks5_handshake(client_socket, session);
    }

    if (isalpha(first_bytes[0])) {
        return handle_http_handshake(client_socket, session);
    }

    return -1;
}

static SOCKET connect_destination_socket(const Destination* destination) {
    struct addrinfo hints;
    struct addrinfo* result = NULL;
    struct addrinfo* item = NULL;
    char port_string[16];
    SOCKET socket_fd = INVALID_SOCKET;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    snprintf(port_string, sizeof(port_string), "%u", (unsigned int)destination->port);

    if (destination->type == DEST_ADDR_DOMAIN) {
        if (getaddrinfo(destination->host, port_string, &hints, &result) != 0) {
            return INVALID_SOCKET;
        }
    } else {
        struct sockaddr_storage storage;
        struct sockaddr* addr = (struct sockaddr*)&storage;
        int addr_len = 0;

        memset(&storage, 0, sizeof(storage));
        if (destination->type == DEST_ADDR_IPV4) {
            struct sockaddr_in* addr4 = (struct sockaddr_in*)&storage;
            addr4->sin_family = AF_INET;
            addr4->sin_port = htons(destination->port);
            memcpy(&addr4->sin_addr, destination->raw_addr, 4);
            addr_len = (int)sizeof(*addr4);
        } else if (destination->type == DEST_ADDR_IPV6) {
            struct sockaddr_in6* addr6 = (struct sockaddr_in6*)&storage;
            addr6->sin6_family = AF_INET6;
            addr6->sin6_port = htons(destination->port);
            memcpy(&addr6->sin6_addr, destination->raw_addr, 16);
            addr_len = (int)sizeof(*addr6);
        } else {
            return INVALID_SOCKET;
        }

        socket_fd = socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
        if (socket_fd == INVALID_SOCKET) {
            return INVALID_SOCKET;
        }
        if (connect(socket_fd, addr, addr_len) == 0) {
            return socket_fd;
        }
        closesocket(socket_fd);
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

    if (result != NULL) {
        freeaddrinfo(result);
    }
    return socket_fd;
}

int proxy_direct_client(SOCKET client_socket, const ProxySession* session) {
    SOCKET remote_socket = INVALID_SOCKET;
    uint8_t buffer[4096];

    remote_socket = connect_destination_socket(&session->destination);
    if (remote_socket == INVALID_SOCKET) {
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
            closesocket(remote_socket);
            return -1;
        }
    } else if (session->handshake_type == CLIENT_HANDSHAKE_HTTP_CONNECT) {
        if (send_http_connect_reply(client_socket, 200) != 0) {
            closesocket(remote_socket);
            return -1;
        }
    } else if (session->initial_data_len > 0 && send_all_socket(remote_socket, session->initial_data, session->initial_data_len) != 0) {
        closesocket(remote_socket);
        return -1;
    }

    for (;;) {
        fd_set read_fds;
        SOCKET max_socket = client_socket > remote_socket ? client_socket : remote_socket;

        FD_ZERO(&read_fds);
        FD_SET(client_socket, &read_fds);
        FD_SET(remote_socket, &read_fds);

        if (select((int)(max_socket + 1), &read_fds, NULL, NULL, NULL) == SOCKET_ERROR) {
            break;
        }

        if (FD_ISSET(client_socket, &read_fds)) {
            int received = recv(client_socket, (char*)buffer, sizeof(buffer), 0);
            if (received <= 0 || send_all_socket(remote_socket, buffer, (size_t)received) != 0) {
                break;
            }
        }

        if (FD_ISSET(remote_socket, &read_fds)) {
            int received = recv(remote_socket, (char*)buffer, sizeof(buffer), 0);
            if (received <= 0 || send_all_socket(client_socket, buffer, (size_t)received) != 0) {
                break;
            }
        }
    }

    shutdown(remote_socket, SD_BOTH);
    closesocket(remote_socket);
    return 0;
}
