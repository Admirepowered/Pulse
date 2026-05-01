#ifndef VLESS_H
#define VLESS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CONFIG_VALUE_LEN 256
#define CONFIG_PATH_LEN 512
#define ENDPOINT_NAME_LEN 128
#define ENDPOINT_LABEL_LEN 256
#define REGION_NAME_LEN 64
#define RULE_NAME_LEN 64
#define MAX_ENDPOINTS 256
#define MAX_RULES 128
#define MAX_RULE_MATCHES 64
#define MAX_REGIONS 32
#define MAX_REGION_CIDRS 256
#define MAX_INITIAL_DATA_LEN 16384

typedef enum {
    INBOUND_TYPE_SOCKS5 = 0,
    INBOUND_TYPE_HTTP,
    INBOUND_TYPE_MIXED
} InboundType;

typedef enum {
    ENDPOINT_TYPE_NONE = 0,
    ENDPOINT_TYPE_VLESS,
    ENDPOINT_TYPE_HYSTERIA2,
    ENDPOINT_TYPE_SHADOWSOCKS,
    ENDPOINT_TYPE_SHADOWSOCKSR,
    ENDPOINT_TYPE_VMESS,
    ENDPOINT_TYPE_TROJAN,
    ENDPOINT_TYPE_TUIC,
    ENDPOINT_TYPE_ANYTLS
} EndpointType;

typedef struct {
    char path[CONFIG_VALUE_LEN];
    char host[CONFIG_VALUE_LEN];
} WsOptions;

typedef struct {
    bool enabled;
    char uuid[37];
    bool tls;
    char flow[64];
    char client_fingerprint[64];
    char servername[CONFIG_VALUE_LEN];
    char network[16];
    WsOptions ws;
} VlessOptions;

typedef struct {
    bool enabled;
    char password[128];
    char sni[CONFIG_VALUE_LEN];
} Hysteria2Options;

typedef struct {
    bool enabled;
    char password[128];
    bool tls;
    char servername[CONFIG_VALUE_LEN];
    char network[16];
    char client_fingerprint[64];
    WsOptions ws;
} TrojanOptions;

typedef struct {
    bool enabled;
    char method[64];
    char password[128];
    char plugin[128];
} ShadowsocksOptions;

typedef struct {
    bool enabled;
    char method[64];
    char password[128];
    char protocol[64];
    char protocol_param[128];
    char obfs[64];
    char obfs_param[128];
} ShadowsocksROptions;

typedef struct {
    bool enabled;
    char uuid[37];
    int alter_id;
    char security[32];
    bool authenticated_length;
    bool tls;
    char servername[CONFIG_VALUE_LEN];
    char network[16];
    char client_fingerprint[64];
    WsOptions ws;
} VMessOptions;

typedef struct {
    bool enabled;
    char uuid[37];
    char password[128];
    char congestion_control[32];
    char udp_relay_mode[32];
    char sni[CONFIG_VALUE_LEN];
    bool zero_rtt;
    char alpn[64];
} TuicOptions;

typedef struct {
    bool enabled;
    char password[128];
    bool tls;
    char servername[CONFIG_VALUE_LEN];
    char client_fingerprint[64];
} AnyTlsOptions;

typedef struct {
    char key[ENDPOINT_NAME_LEN];
    char name[ENDPOINT_LABEL_LEN];
    char source_alias[ENDPOINT_NAME_LEN];
    EndpointType type;
    bool enabled;
    bool imported;
    char server[CONFIG_VALUE_LEN];
    int port;
    bool udp;
    bool skip_cert_verify;
    VlessOptions vless;
    Hysteria2Options hysteria2;
    TrojanOptions trojan;
    ShadowsocksOptions shadowsocks;
    ShadowsocksROptions shadowsocksr;
    VMessOptions vmess;
    TuicOptions tuic;
    AnyTlsOptions anytls;
} EndpointConfig;

typedef struct {
    int family;
    int prefix_len;
    unsigned char addr[16];
    char text[64];
} RegionCidr;

typedef struct {
    char name[REGION_NAME_LEN];
    RegionCidr cidrs[MAX_REGION_CIDRS];
    int cidr_count;
} RegionConfig;

typedef enum {
    ROUTE_ACTION_NONE = 0,
    ROUTE_ACTION_PROXY,
    ROUTE_ACTION_DIRECT,
    ROUTE_ACTION_REJECT
} RouteAction;

typedef struct {
    char name[RULE_NAME_LEN];
    RouteAction action;
    char endpoint[ENDPOINT_NAME_LEN];
    char domains[MAX_RULE_MATCHES][CONFIG_VALUE_LEN];
    int domain_count;
    char domain_suffixes[MAX_RULE_MATCHES][CONFIG_VALUE_LEN];
    int domain_suffix_count;
    char domain_keywords[MAX_RULE_MATCHES][CONFIG_VALUE_LEN];
    int domain_keyword_count;
    char region[REGION_NAME_LEN];
    char region_db[REGION_NAME_LEN];
    bool resolve;
} RouteRule;

typedef struct {
    InboundType type;
    char local_bind_addr[64];
    int local_port;
    char active_endpoint[ENDPOINT_NAME_LEN];
    char country_db_path[CONFIG_PATH_LEN];
    void* country_db_handle;
    EndpointConfig endpoints[MAX_ENDPOINTS];
    int endpoint_count;
    RouteRule rules[MAX_RULES];
    int rule_count;
    RegionConfig regions[MAX_REGIONS];
    int region_count;
} Config;

typedef enum {
    DEST_ADDR_IPV4 = 0x01,
    DEST_ADDR_DOMAIN = 0x02,
    DEST_ADDR_IPV6 = 0x03
} DestinationType;

typedef struct {
    DestinationType type;
    uint8_t raw_addr[16];
    size_t raw_addr_len;
    char host[256];
    uint16_t port;
} Destination;

typedef struct {
    RouteAction action;
    const EndpointConfig* endpoint;
    const RouteRule* rule;
} RouteDecision;

typedef enum {
    CLIENT_HANDSHAKE_SOCKS5 = 0,
    CLIENT_HANDSHAKE_HTTP_CONNECT,
    CLIENT_HANDSHAKE_HTTP_FORWARD
} ClientHandshakeType;

typedef struct {
    ClientHandshakeType handshake_type;
    Destination destination;
    uint8_t initial_data[MAX_INITIAL_DATA_LEN];
    size_t initial_data_len;
} ProxySession;

int load_config(const char* filename, Config* config);
void cleanup_config(Config* config);
const EndpointConfig* get_active_endpoint(const Config* config);
const EndpointConfig* find_endpoint_by_name(const Config* config, const char* key);
int resolve_route(const Config* config, const Destination* destination, RouteDecision* decision);
int start_proxy(const Config* config);
int download_subscription_command(const char* url, const char* proxy_spec);
int import_subscription_file_command(const char* input_path, const char* output_name);
const char* endpoint_type_name(EndpointType type);
const char* inbound_type_name(InboundType type);

#endif
