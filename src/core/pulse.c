#include <string.h>
#include "core/pulse.h"

const char* endpoint_type_name(EndpointType type) {
    switch (type) {
        case ENDPOINT_TYPE_VLESS:
            return "vless";
        case ENDPOINT_TYPE_HYSTERIA2:
            return "hysteria2";
        case ENDPOINT_TYPE_SHADOWSOCKS:
            return "ss";
        case ENDPOINT_TYPE_SHADOWSOCKSR:
            return "ssr";
        case ENDPOINT_TYPE_VMESS:
            return "vmess";
        case ENDPOINT_TYPE_TROJAN:
            return "trojan";
        case ENDPOINT_TYPE_TUIC:
            return "tuic";
        case ENDPOINT_TYPE_ANYTLS:
            return "anytls";
        default:
            return "unknown";
    }
}

const char* inbound_type_name(InboundType type) {
    switch (type) {
        case INBOUND_TYPE_SOCKS5:
            return "socks5";
        case INBOUND_TYPE_HTTP:
            return "http";
        case INBOUND_TYPE_MIXED:
            return "mixed";
        default:
            return "unknown";
    }
}
