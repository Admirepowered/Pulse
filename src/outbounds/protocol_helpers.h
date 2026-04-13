#ifndef PULSE_PROTOCOL_HELPERS_H
#define PULSE_PROTOCOL_HELPERS_H

#include "core/proxy.h"
#include "outbounds/stream.h"

int encode_destination_socksaddr(const Destination* destination, int include_cmd, uint8_t* out, size_t out_size, size_t* out_len);
int encode_destination_streamaddr(const Destination* destination, uint8_t* out, size_t out_size, size_t* out_len);
int relay_remote_stream_client(SOCKET client_socket, RemoteStream* remote_stream, const ProxySession* session);

#endif
