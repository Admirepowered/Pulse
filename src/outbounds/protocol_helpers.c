#include <string.h>
#include "outbounds/protocol_helpers.h"

static uint8_t destination_type_to_stream_atyp(DestinationType type) {
    switch (type) {
        case DEST_ADDR_IPV4:
            return 0x01;
        case DEST_ADDR_DOMAIN:
            return 0x03;
        case DEST_ADDR_IPV6:
            return 0x04;
        default:
            return 0x00;
    }
}

int encode_destination_socksaddr(const Destination* destination, int include_cmd, uint8_t* out, size_t out_size, size_t* out_len) {
    size_t offset = 0;
    uint8_t atyp = destination_type_to_stream_atyp(destination->type);

    if (include_cmd) {
        if (out_size < 1) {
            return -1;
        }
        out[offset++] = 0x01;
    }

    if (out_size < offset + 1 + 2) {
        return -1;
    }

    if (atyp == 0x00) {
        return -1;
    }

    out[offset++] = atyp;

    if (destination->type == DEST_ADDR_DOMAIN) {
        size_t host_len = strlen(destination->host);
        if (host_len == 0 || host_len > 255 || out_size < offset + 1 + host_len + 2) {
            return -1;
        }
        out[offset++] = (uint8_t)host_len;
        memcpy(out + offset, destination->host, host_len);
        offset += host_len;
    } else if (destination->type == DEST_ADDR_IPV4 || destination->type == DEST_ADDR_IPV6) {
        if (out_size < offset + destination->raw_addr_len + 2) {
            return -1;
        }
        memcpy(out + offset, destination->raw_addr, destination->raw_addr_len);
        offset += destination->raw_addr_len;
    } else {
        return -1;
    }

    out[offset++] = (uint8_t)((destination->port >> 8) & 0xff);
    out[offset++] = (uint8_t)(destination->port & 0xff);
    *out_len = offset;
    return 0;
}

int encode_destination_streamaddr(const Destination* destination, uint8_t* out, size_t out_size, size_t* out_len) {
    return encode_destination_socksaddr(destination, 0, out, out_size, out_len);
}

int relay_remote_stream_client(SOCKET client_socket, RemoteStream* remote_stream, const ProxySession* session) {
    uint8_t buffer[PULSE_IO_BUFFER_SIZE];

    for (;;) {
        fd_set read_fds;
        int client_ready = 0;
        int remote_ready = 0;

        if (remote_stream_has_pending_data(remote_stream)) {
            remote_ready = 1;
        } else {
            FD_ZERO(&read_fds);
            FD_SET(client_socket, &read_fds);
            FD_SET(remote_stream->socket_fd, &read_fds);

            {
                SOCKET max_socket = client_socket > remote_stream->socket_fd ? client_socket : remote_stream->socket_fd;
                if (select((int)(max_socket + 1), &read_fds, NULL, NULL, NULL) == SOCKET_ERROR) {
                    break;
                }
            }

            client_ready = FD_ISSET(client_socket, &read_fds);
            remote_ready = FD_ISSET(remote_stream->socket_fd, &read_fds);
        }

        if (client_ready) {
            int received = recv(client_socket, (char*)buffer, sizeof(buffer), 0);
            if (received <= 0) {
                break;
            }

            if (remote_stream_send(remote_stream, buffer, (size_t)received) != 0) {
                break;
            }
        }

        if (remote_ready) {
            int received = remote_stream_recv(remote_stream, buffer, sizeof(buffer));
            if (received <= 0) {
                break;
            }

            if (send_all_socket(client_socket, buffer, (size_t)received) != 0) {
                break;
            }
        }
    }

    (void)session;
    return 0;
}
