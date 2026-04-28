#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "core/proxy.h"
#include "core/mmdb.h"

static void safe_copy(char* dest, size_t dest_size, const char* src);

#define MAX_LOADED_CONFIGS 64
#define MAX_LINE_LEN 2048

typedef enum {
    SECTION_NONE = 0,
    SECTION_LOCAL,
    SECTION_MAIN,
    SECTION_ENDPOINT,
    SECTION_ENDPOINT_WS_OPTS,
    SECTION_RULE,
    SECTION_REGION
} ParseSectionType;

typedef struct {
    ParseSectionType type;
    EndpointConfig* endpoint;
    RouteRule* rule;
    RegionConfig* region;
} ParseSection;

typedef struct {
    char path[CONFIG_PATH_LEN];
} LoadedConfigPath;

typedef struct {
    LoadedConfigPath items[MAX_LOADED_CONFIGS];
    int count;
} LoadState;

typedef struct {
    Config* config;
    LoadState* state;
    const char* canonical_path;
    char directory[CONFIG_PATH_LEN];
    char import_alias[ENDPOINT_NAME_LEN];
    int is_root;
} ParseContext;

static void safe_copy(char* dest, size_t dest_size, const char* src) {
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

static void strip_comment(char* text) {
    int in_string = 0;
    char quote = '\0';
    size_t i = 0;

    for (i = 0; text[i] != '\0'; ++i) {
        if (in_string) {
            if (text[i] == '\\' && text[i + 1] != '\0') {
                ++i;
                continue;
            }
            if (text[i] == quote) {
                in_string = 0;
                quote = '\0';
            }
            continue;
        }

        if (text[i] == '"' || text[i] == '\'') {
            in_string = 1;
            quote = text[i];
            continue;
        }

        if (text[i] == '#') {
            text[i] = '\0';
            break;
        }
    }
}

static void unquote_inplace(char* text) {
    size_t len = strlen(text);

    if (len >= 2 && ((text[0] == '"' && text[len - 1] == '"') || (text[0] == '\'' && text[len - 1] == '\''))) {
        memmove(text, text + 1, len - 2);
        text[len - 2] = '\0';
    }
}

static int parse_bool_value(const char* value, int* out) {
    if (_stricmp(value, "true") == 0) {
        *out = 1;
        return 0;
    }
    if (_stricmp(value, "false") == 0) {
        *out = 0;
        return 0;
    }
    return -1;
}

static int parse_port_value(const char* value, int* out) {
    char* end = NULL;
    long parsed = strtol(value, &end, 10);

    if (end == value || *end != '\0' || parsed <= 0 || parsed > 65535) {
        return -1;
    }

    *out = (int)parsed;
    return 0;
}

static EndpointType parse_endpoint_type(const char* value) {
    if (_stricmp(value, "vless") == 0) {
        return ENDPOINT_TYPE_VLESS;
    }
    if (_stricmp(value, "hysteria2") == 0 || _stricmp(value, "hy2") == 0) {
        return ENDPOINT_TYPE_HYSTERIA2;
    }
    if (_stricmp(value, "ss") == 0 || _stricmp(value, "shadowsocks") == 0) {
        return ENDPOINT_TYPE_SHADOWSOCKS;
    }
    if (_stricmp(value, "ssr") == 0 || _stricmp(value, "shadowsocksr") == 0) {
        return ENDPOINT_TYPE_SHADOWSOCKSR;
    }
    if (_stricmp(value, "vmess") == 0) {
        return ENDPOINT_TYPE_VMESS;
    }
    if (_stricmp(value, "trojan") == 0) {
        return ENDPOINT_TYPE_TROJAN;
    }
    if (_stricmp(value, "tuic") == 0) {
        return ENDPOINT_TYPE_TUIC;
    }
    if (_stricmp(value, "anytls") == 0) {
        return ENDPOINT_TYPE_ANYTLS;
    }
    return ENDPOINT_TYPE_NONE;
}

static InboundType parse_inbound_type(const char* value) {
    if (_stricmp(value, "socks") == 0 || _stricmp(value, "socks5") == 0) {
        return INBOUND_TYPE_SOCKS5;
    }
    if (_stricmp(value, "http") == 0) {
        return INBOUND_TYPE_HTTP;
    }
    if (_stricmp(value, "mixed") == 0) {
        return INBOUND_TYPE_MIXED;
    }
    return INBOUND_TYPE_SOCKS5;
}

static RouteAction parse_route_action(const char* value) {
    if (_stricmp(value, "proxy") == 0) {
        return ROUTE_ACTION_PROXY;
    }
    if (_stricmp(value, "direct") == 0) {
        return ROUTE_ACTION_DIRECT;
    }
    if (_stricmp(value, "reject") == 0 || _stricmp(value, "block") == 0) {
        return ROUTE_ACTION_REJECT;
    }
    return ROUTE_ACTION_NONE;
}

static int is_numeric_key(const char* text) {
    size_t i = 0;

    if (text == NULL || text[0] == '\0') {
        return 0;
    }

    for (i = 0; text[i] != '\0'; ++i) {
        if (!isdigit((unsigned char)text[i])) {
            return 0;
        }
    }

    return 1;
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

static int string_contains_ci(const char* text, const char* needle) {
    size_t text_len = strlen(text);
    size_t needle_len = strlen(needle);
    size_t i = 0;

    if (needle_len == 0) {
        return 1;
    }
    if (needle_len > text_len) {
        return 0;
    }

    for (i = 0; i + needle_len <= text_len; ++i) {
        size_t j = 0;
        int matched = 1;

        for (j = 0; j < needle_len; ++j) {
            if (tolower((unsigned char)text[i + j]) != tolower((unsigned char)needle[j])) {
                matched = 0;
                break;
            }
        }

        if (matched) {
            return 1;
        }
    }

    return 0;
}

static int string_equals_ci(const char* a, const char* b) {
    return _stricmp(a, b) == 0;
}

static int path_is_absolute(const char* path) {
    if (path == NULL || path[0] == '\0') {
        return 0;
    }

    if (path[0] == '/' || path[0] == '\\') {
        return 1;
    }

    return isalpha((unsigned char)path[0]) &&
        path[1] == ':' &&
        (path[2] == '/' || path[2] == '\\');
}

static void path_dirname(const char* path, char* out, size_t out_size) {
    const char* slash = strrchr(path, '/');
    const char* backslash = strrchr(path, '\\');
    const char* sep = slash;

    if (backslash != NULL && (sep == NULL || backslash > sep)) {
        sep = backslash;
    }

    if (sep == NULL) {
        safe_copy(out, out_size, ".");
        return;
    }

    if (sep == path) {
        safe_copy(out, out_size, "/");
        return;
    }

    {
        size_t len = (size_t)(sep - path);
        if (len >= out_size) {
            len = out_size - 1;
        }
        memcpy(out, path, len);
        out[len] = '\0';
    }
}

static const char* path_basename_ptr(const char* path) {
    const char* slash = strrchr(path, '/');
    const char* backslash = strrchr(path, '\\');
    const char* base = path;

    if (slash != NULL && slash + 1 > base) {
        base = slash + 1;
    }
    if (backslash != NULL && backslash + 1 > base) {
        base = backslash + 1;
    }

    return base;
}

static void path_stem_from_basename(const char* basename, char* out, size_t out_size) {
    const char* dot = strrchr(basename, '.');

    if (dot == NULL || dot == basename) {
        safe_copy(out, out_size, basename);
        return;
    }

    {
        size_t len = (size_t)(dot - basename);
        if (len >= out_size) {
            len = out_size - 1;
        }
        memcpy(out, basename, len);
        out[len] = '\0';
    }
}

static void path_join(const char* base_dir, const char* child, char* out, size_t out_size) {
    if (path_is_absolute(child) || base_dir == NULL || base_dir[0] == '\0' || strcmp(base_dir, ".") == 0) {
        safe_copy(out, out_size, child);
        return;
    }

    snprintf(out, out_size, "%s/%s", base_dir, child);
}

static int path_file_exists(const char* path) {
    FILE* fp = NULL;

    if (path == NULL || path[0] == '\0') {
        return 0;
    }

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return 0;
    }

    fclose(fp);
    return 1;
}

static void resolve_include_path(const char* base_dir, const char* include_path, char* out, size_t out_size) {
    char candidate[CONFIG_PATH_LEN];

    if (path_is_absolute(include_path) || base_dir == NULL || base_dir[0] == '\0' || strcmp(base_dir, ".") == 0) {
        safe_copy(out, out_size, include_path);
        return;
    }

    path_join(base_dir, include_path, candidate, sizeof(candidate));
    if (path_file_exists(candidate) || !path_file_exists(include_path)) {
        safe_copy(out, out_size, candidate);
        return;
    }

    safe_copy(out, out_size, include_path);
}

static void normalize_slashes(char* path) {
    size_t i = 0;

    for (i = 0; path[i] != '\0'; ++i) {
        if (path[i] == '\\') {
            path[i] = '/';
        }
    }
}

static int canonicalize_path(const char* path, char* out, size_t out_size) {
#if PLATFORM_IS_WINDOWS
    DWORD result = GetFullPathNameA(path, (DWORD)out_size, out, NULL);
    if (result == 0 || result >= out_size) {
        safe_copy(out, out_size, path);
        normalize_slashes(out);
        return -1;
    }
#else
    char* resolved = realpath(path, NULL);
    if (resolved == NULL) {
        safe_copy(out, out_size, path);
        normalize_slashes(out);
        return -1;
    }
    safe_copy(out, out_size, resolved);
    free(resolved);
#endif
    normalize_slashes(out);
    return 0;
}

static int load_state_contains(const LoadState* state, const char* canonical_path) {
    int i = 0;

    for (i = 0; i < state->count; ++i) {
        if (_stricmp(state->items[i].path, canonical_path) == 0) {
            return 1;
        }
    }

    return 0;
}

static int load_state_add(LoadState* state, const char* canonical_path) {
    if (load_state_contains(state, canonical_path)) {
        return 0;
    }

    if (state->count >= MAX_LOADED_CONFIGS) {
        return -1;
    }

    safe_copy(state->items[state->count].path, sizeof(state->items[state->count].path), canonical_path);
    ++state->count;
    return 0;
}

static int parse_list_items(const char* value, char* out, size_t item_size, int max_count, int* count) {
    char buffer[MAX_LINE_LEN];
    char* text = buffer;
    int item_count = 0;

    safe_copy(buffer, sizeof(buffer), value);
    trim_inplace(text);

    if (text[0] == '\0') {
        return -1;
    }

    if (text[0] != '[') {
        if (max_count < 1) {
            return -1;
        }
        unquote_inplace(text);
        trim_inplace(text);
        safe_copy(out, item_size, text);
        *count = 1;
        return 0;
    }

    {
        size_t len = strlen(text);
        if (len < 2 || text[len - 1] != ']') {
            return -1;
        }
        text[len - 1] = '\0';
        ++text;
    }

    for (;;) {
        char item[CONFIG_PATH_LEN];
        size_t item_len = 0;
        int in_string = 0;
        char quote = '\0';

        while (*text != '\0' && isspace((unsigned char)*text)) {
            ++text;
        }

        if (*text == '\0') {
            break;
        }

        while (*text != '\0') {
            if (in_string) {
                if (*text == '\\' && text[1] != '\0') {
                    if (item_len + 1 >= sizeof(item) - 1) {
                        return -1;
                    }
                    item[item_len++] = text[1];
                    text += 2;
                    continue;
                }

                if (*text == quote) {
                    in_string = 0;
                    ++text;
                    continue;
                }

                if (item_len + 1 >= sizeof(item) - 1) {
                    return -1;
                }
                item[item_len++] = *text++;
                continue;
            }

            if (*text == '"' || *text == '\'') {
                in_string = 1;
                quote = *text++;
                continue;
            }

            if (*text == ',') {
                break;
            }

            if (item_len + 1 >= sizeof(item) - 1) {
                return -1;
            }
            item[item_len++] = *text++;
        }

        item[item_len] = '\0';
        trim_inplace(item);

        if (item[0] != '\0') {
            if (item_count >= max_count) {
                return -1;
            }
            safe_copy(out + (size_t)item_count * item_size, item_size, item);
            ++item_count;
        }

        if (*text == ',') {
            ++text;
            continue;
        }

        break;
    }

    *count = item_count;
    return item_count > 0 ? 0 : -1;
}

static void set_config_defaults(Config* config) {
    memset(config, 0, sizeof(*config));
    config->type = INBOUND_TYPE_MIXED;
    strcpy(config->local_bind_addr, "127.0.0.1");
    config->local_port = 1080;
}

static void set_endpoint_defaults(EndpointConfig* endpoint) {
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->enabled = true;
    endpoint->port = 443;
    endpoint->vless.enabled = true;
    endpoint->vless.tls = true;
    strcpy(endpoint->vless.network, "ws");
    strcpy(endpoint->vless.ws.path, "/");
    endpoint->trojan.tls = true;
    strcpy(endpoint->trojan.network, "tcp");
    strcpy(endpoint->trojan.ws.path, "/");
    strcpy(endpoint->vmess.security, "auto");
    endpoint->vmess.authenticated_length = false;
    endpoint->vmess.tls = true;
    strcpy(endpoint->vmess.network, "ws");
    strcpy(endpoint->vmess.ws.path, "/");
    strcpy(endpoint->shadowsocks.method, "aes-256-gcm");
    strcpy(endpoint->shadowsocksr.method, "aes-256-cfb");
    strcpy(endpoint->shadowsocksr.protocol, "origin");
    strcpy(endpoint->shadowsocksr.obfs, "plain");
    endpoint->anytls.tls = true;
}

static void set_rule_defaults(RouteRule* rule) {
    memset(rule, 0, sizeof(*rule));
    rule->action = ROUTE_ACTION_PROXY;
}

static RegionConfig* find_region(Config* config, const char* name) {
    int i = 0;

    for (i = 0; i < config->region_count; ++i) {
        if (_stricmp(config->regions[i].name, name) == 0) {
            return &config->regions[i];
        }
    }

    return NULL;
}

static RegionConfig* ensure_region(Config* config, const char* name) {
    RegionConfig* region = find_region(config, name);

    if (region != NULL) {
        return region;
    }

    if (config->region_count >= MAX_REGIONS) {
        return NULL;
    }

    region = &config->regions[config->region_count++];
    memset(region, 0, sizeof(*region));
    safe_copy(region->name, sizeof(region->name), name);
    return region;
}

static RouteRule* ensure_rule(Config* config, const char* name) {
    int i = 0;

    for (i = 0; i < config->rule_count; ++i) {
        if (_stricmp(config->rules[i].name, name) == 0) {
            return &config->rules[i];
        }
    }

    if (config->rule_count >= MAX_RULES) {
        return NULL;
    }

    set_rule_defaults(&config->rules[config->rule_count]);
    safe_copy(config->rules[config->rule_count].name, sizeof(config->rules[config->rule_count].name), name);
    ++config->rule_count;
    return &config->rules[config->rule_count - 1];
}

static void make_endpoint_storage_key(const char* alias, const char* key, char* out, size_t out_size) {
    if (alias != NULL && alias[0] != '\0') {
        snprintf(out, out_size, "%s:%s", alias, key);
        return;
    }

    safe_copy(out, out_size, key);
}

static EndpointConfig* find_endpoint_raw(Config* config, const char* key) {
    int i = 0;

    for (i = 0; i < config->endpoint_count; ++i) {
        if (_stricmp(config->endpoints[i].key, key) == 0) {
            return &config->endpoints[i];
        }
    }

    return NULL;
}

static const EndpointConfig* find_endpoint_by_name_internal(const Config* config, const char* key, int include_disabled) {
    int i = 0;
    char resolved[ENDPOINT_NAME_LEN];

    if (key == NULL || key[0] == '\0') {
        return NULL;
    }

    for (i = 0; i < config->endpoint_count; ++i) {
        if (_stricmp(config->endpoints[i].key, key) == 0 &&
            (include_disabled || config->endpoints[i].enabled)) {
            return &config->endpoints[i];
        }
    }

    {
        const char* bracket = strchr(key, '[');
        size_t key_len = strlen(key);

        if (bracket != NULL && key_len > 2 && key[key_len - 1] == ']') {
            char alias[ENDPOINT_NAME_LEN];
            char inner[ENDPOINT_NAME_LEN];
            size_t alias_len = (size_t)(bracket - key);
            size_t inner_len = key_len - alias_len - 2;

            if (alias_len > 0 && alias_len < sizeof(alias) && inner_len > 0 && inner_len < sizeof(inner)) {
                memcpy(alias, key, alias_len);
                alias[alias_len] = '\0';
                memcpy(inner, bracket + 1, inner_len);
                inner[inner_len] = '\0';
                make_endpoint_storage_key(alias, inner, resolved, sizeof(resolved));
                for (i = 0; i < config->endpoint_count; ++i) {
                    if (_stricmp(config->endpoints[i].key, resolved) == 0 &&
                        (include_disabled || config->endpoints[i].enabled)) {
                        return &config->endpoints[i];
                    }
                }

                if (is_numeric_key(inner)) {
                    int target_index = atoi(inner);
                    int current_index = 0;

                    for (i = 0; i < config->endpoint_count; ++i) {
                        const EndpointConfig* endpoint = &config->endpoints[i];

                        if (!endpoint->imported || _stricmp(endpoint->source_alias, alias) != 0) {
                            continue;
                        }

                        if (current_index == target_index) {
                            if (include_disabled || endpoint->enabled) {
                                return endpoint;
                            }
                            return NULL;
                        }

                        ++current_index;
                    }
                }
            }
        }
    }

    return NULL;
}

const EndpointConfig* find_endpoint_by_name(const Config* config, const char* key) {
    return find_endpoint_by_name_internal(config, key, 0);
}

static EndpointConfig* ensure_endpoint(Config* config, const char* key, const ParseContext* context) {
    char storage_key[ENDPOINT_NAME_LEN];
    EndpointConfig* endpoint = NULL;

    if (!context->is_root && key[0] == '\0') {
        return NULL;
    }

    if (context->is_root && is_numeric_key(key)) {
        return NULL;
    }

    make_endpoint_storage_key(context->is_root ? "" : context->import_alias, key, storage_key, sizeof(storage_key));

    endpoint = find_endpoint_raw(config, storage_key);
    if (endpoint != NULL) {
        return endpoint;
    }

    if (config->endpoint_count >= MAX_ENDPOINTS) {
        return NULL;
    }

    endpoint = &config->endpoints[config->endpoint_count++];
    set_endpoint_defaults(endpoint);
    safe_copy(endpoint->key, sizeof(endpoint->key), storage_key);
    safe_copy(endpoint->name, sizeof(endpoint->name), key);
    if (!context->is_root) {
        endpoint->imported = true;
        safe_copy(endpoint->source_alias, sizeof(endpoint->source_alias), context->import_alias);
    }
    return endpoint;
}

static int parse_ws_headers(const char* value, EndpointConfig* endpoint) {
    const char* host_key = strstr(value, "Host");
    const char* start = NULL;
    const char* end = NULL;
    char host[CONFIG_VALUE_LEN];
    size_t len = 0;

    if (host_key == NULL) {
        host_key = strstr(value, "host");
    }
    if (host_key == NULL) {
        return 0;
    }

    start = strchr(host_key, '=');
    if (start == NULL) {
        return -1;
    }
    ++start;

    while (*start != '\0' && isspace((unsigned char)*start)) {
        ++start;
    }

    if (*start != '"' && *start != '\'') {
        return -1;
    }

    end = strchr(start + 1, *start);
    if (end == NULL) {
        return -1;
    }

    len = (size_t)(end - (start + 1));
    if (len >= sizeof(host)) {
        return -1;
    }

    memcpy(host, start + 1, len);
    host[len] = '\0';
    safe_copy(endpoint->vless.ws.host, sizeof(endpoint->vless.ws.host), host);
    return 0;
}

static int parse_cidr_value(const char* value, RegionCidr* cidr) {
    char buffer[64];
    char* slash = NULL;
    char* end = NULL;
    long prefix = 0;

    safe_copy(buffer, sizeof(buffer), value);
    trim_inplace(buffer);
    slash = strchr(buffer, '/');
    if (slash == NULL) {
        return -1;
    }

    *slash = '\0';
    ++slash;

    prefix = strtol(slash, &end, 10);
    if (end == slash || *end != '\0') {
        return -1;
    }

    memset(cidr, 0, sizeof(*cidr));

    if (inet_pton(AF_INET, buffer, cidr->addr) == 1) {
        if (prefix < 0 || prefix > 32) {
            return -1;
        }
        cidr->family = AF_INET;
        cidr->prefix_len = (int)prefix;
    } else if (inet_pton(AF_INET6, buffer, cidr->addr) == 1) {
        if (prefix < 0 || prefix > 128) {
            return -1;
        }
        cidr->family = AF_INET6;
        cidr->prefix_len = (int)prefix;
    } else {
        return -1;
    }

    safe_copy(cidr->text, sizeof(cidr->text), value);
    return 0;
}

static int parse_region_cidrs(const char* value, RegionConfig* region) {
    char items[MAX_RULE_MATCHES][CONFIG_VALUE_LEN];
    int count = 0;
    int i = 0;

    if (parse_list_items(value, (char*)items, sizeof(items[0]), MAX_RULE_MATCHES, &count) != 0) {
        return -1;
    }

    for (i = 0; i < count; ++i) {
        if (region->cidr_count >= MAX_REGION_CIDRS) {
            return -1;
        }
        if (parse_cidr_value(items[i], &region->cidrs[region->cidr_count]) != 0) {
            return -1;
        }
        ++region->cidr_count;
    }

    return 0;
}

static int parse_section_header(ParseContext* context, char* line, ParseSection* section) {
    char* path = line;
    char* ws_opts = NULL;
    size_t len = strlen(line);

    section->type = SECTION_NONE;
    section->endpoint = NULL;
    section->rule = NULL;
    section->region = NULL;

    if (len < 2 || line[0] != '[' || line[len - 1] != ']') {
        return -1;
    }

    line[len - 1] = '\0';
    memmove(line, line + 1, len - 1);
    trim_inplace(line);

    if (strcmp(line, "local") == 0) {
        if (!context->is_root) {
            return -1;
        }
        section->type = SECTION_LOCAL;
        return 0;
    }

    if (strcmp(line, "main") == 0) {
        if (!context->is_root) {
            return -1;
        }
        section->type = SECTION_MAIN;
        return 0;
    }

    if (starts_with_ci(line, "rules.")) {
        if (!context->is_root) {
            return -1;
        }
        section->rule = ensure_rule(context->config, line + 6);
        if (section->rule == NULL) {
            return -1;
        }
        section->type = SECTION_RULE;
        return 0;
    }

    if (starts_with_ci(line, "regions.")) {
        if (!context->is_root) {
            return -1;
        }
        section->region = ensure_region(context->config, line + 8);
        if (section->region == NULL) {
            return -1;
        }
        section->type = SECTION_REGION;
        return 0;
    }

    if (!starts_with_ci(line, "endpoints.")) {
        return 0;
    }

    path = line + 10;
    ws_opts = strstr(path, ".ws-opts");
    if (ws_opts != NULL && strcmp(ws_opts, ".ws-opts") == 0) {
        *ws_opts = '\0';
        section->endpoint = ensure_endpoint(context->config, path, context);
        if (section->endpoint == NULL) {
            return -1;
        }
        section->type = SECTION_ENDPOINT_WS_OPTS;
        return 0;
    }

    section->endpoint = ensure_endpoint(context->config, path, context);
    if (section->endpoint == NULL) {
        return -1;
    }
    section->type = SECTION_ENDPOINT;
    return 0;
}

static int load_config_file(const char* filename, const char* alias, int is_root, Config* config, LoadState* state);

static int parse_main_imports(ParseContext* context, const char* value) {
    char items[MAX_RULE_MATCHES][CONFIG_PATH_LEN];
    int count = 0;
    int i = 0;

    if (parse_list_items(value, (char*)items, sizeof(items[0]), MAX_RULE_MATCHES, &count) != 0) {
        return -1;
    }

    for (i = 0; i < count; ++i) {
        char alias_name[ENDPOINT_NAME_LEN];
        char include_path[CONFIG_PATH_LEN];
        char resolved_path[CONFIG_PATH_LEN];
        char* divider = NULL;

        safe_copy(alias_name, sizeof(alias_name), "");
        safe_copy(include_path, sizeof(include_path), items[i]);
        divider = strstr(include_path, "::");
        if (divider != NULL) {
            *divider = '\0';
            safe_copy(alias_name, sizeof(alias_name), include_path);
            memmove(include_path, divider + 2, strlen(divider + 2) + 1);
        }

        resolve_include_path(context->directory, include_path, resolved_path, sizeof(resolved_path));
        if (load_config_file(resolved_path, alias_name[0] != '\0' ? alias_name : NULL, 0, context->config, context->state) != 0) {
            return -1;
        }
    }

    return 0;
}

static int parse_config_entry(ParseContext* context, const ParseSection* section, const char* key, char* value, int line_no) {
    int bool_value = 0;
    int port_value = 0;
    EndpointConfig* endpoint = section->endpoint;
    RouteRule* rule = section->rule;
    RegionConfig* region = section->region;

    if (section->type == SECTION_LOCAL) {
        if (strcmp(key, "type") == 0 || strcmp(key, "protocol") == 0 || strcmp(key, "inbound") == 0) {
            unquote_inplace(value);
            context->config->type = parse_inbound_type(value);
            return 0;
        }
        if (strcmp(key, "bind") == 0 || strcmp(key, "bind_addr") == 0) {
            unquote_inplace(value);
            safe_copy(context->config->local_bind_addr, sizeof(context->config->local_bind_addr), value);
            return 0;
        }
        if (strcmp(key, "port") == 0) {
            if (parse_port_value(value, &port_value) != 0) {
                fprintf(stderr, "Invalid local.port at %s:%d\n", context->canonical_path, line_no);
                return -1;
            }
            context->config->local_port = port_value;
            return 0;
        }
    }

    if (section->type == SECTION_MAIN) {
        if (strcmp(key, "endpoint") == 0 || strcmp(key, "active-endpoint") == 0) {
            unquote_inplace(value);
            safe_copy(context->config->active_endpoint, sizeof(context->config->active_endpoint), value);
            return 0;
        }
        if (strcmp(key, "include") == 0 || strcmp(key, "includes") == 0 ||
            strcmp(key, "import") == 0 || strcmp(key, "imports") == 0) {
            if (parse_main_imports(context, value) != 0) {
                fprintf(stderr, "Invalid main.%s at %s:%d\n", key, context->canonical_path, line_no);
                return -1;
            }
            return 0;
        }
        if (strcmp(key, "country-db") == 0 || strcmp(key, "country_db") == 0 ||
            strcmp(key, "country-db-path") == 0 || strcmp(key, "country_db_path") == 0) {
            unquote_inplace(value);
            safe_copy(context->config->country_db_path, sizeof(context->config->country_db_path), value);
            return 0;
        }
    }

    if (section->type == SECTION_RULE && rule != NULL) {
        if (strcmp(key, "action") == 0 || strcmp(key, "mode") == 0) {
            RouteAction action = ROUTE_ACTION_NONE;
            unquote_inplace(value);
            action = parse_route_action(value);
            if (action == ROUTE_ACTION_NONE) {
                fprintf(stderr, "Invalid rule action at %s:%d\n", context->canonical_path, line_no);
                return -1;
            }
            rule->action = action;
            return 0;
        }
        if (strcmp(key, "endpoint") == 0) {
            unquote_inplace(value);
            safe_copy(rule->endpoint, sizeof(rule->endpoint), value);
            return 0;
        }
        if (strcmp(key, "domains") == 0) {
            if (parse_list_items(value, (char*)rule->domains, sizeof(rule->domains[0]), MAX_RULE_MATCHES, &rule->domain_count) != 0) {
                fprintf(stderr, "Invalid rule domains at %s:%d\n", context->canonical_path, line_no);
                return -1;
            }
            return 0;
        }
        if (strcmp(key, "domain-suffixes") == 0 || strcmp(key, "domain_suffixes") == 0) {
            if (parse_list_items(value, (char*)rule->domain_suffixes, sizeof(rule->domain_suffixes[0]), MAX_RULE_MATCHES, &rule->domain_suffix_count) != 0) {
                fprintf(stderr, "Invalid rule domain suffixes at %s:%d\n", context->canonical_path, line_no);
                return -1;
            }
            return 0;
        }
        if (strcmp(key, "domain-keywords") == 0 || strcmp(key, "domain_keywords") == 0 || strcmp(key, "keywords") == 0) {
            if (parse_list_items(value, (char*)rule->domain_keywords, sizeof(rule->domain_keywords[0]), MAX_RULE_MATCHES, &rule->domain_keyword_count) != 0) {
                fprintf(stderr, "Invalid rule domain keywords at %s:%d\n", context->canonical_path, line_no);
                return -1;
            }
            return 0;
        }
        if (strcmp(key, "region") == 0) {
            unquote_inplace(value);
            safe_copy(rule->region, sizeof(rule->region), value);
            return 0;
        }
        if (strcmp(key, "region-db") == 0 || strcmp(key, "region_db") == 0) {
            unquote_inplace(value);
            safe_copy(rule->region_db, sizeof(rule->region_db), value);
            return 0;
        }
        if (strcmp(key, "resolve") == 0) {
            if (parse_bool_value(value, &bool_value) != 0) {
                fprintf(stderr, "Invalid rule resolve at %s:%d\n", context->canonical_path, line_no);
                return -1;
            }
            rule->resolve = bool_value != 0;
            return 0;
        }
    }

    if (section->type == SECTION_REGION && region != NULL) {
        if (strcmp(key, "cidr") == 0 || strcmp(key, "cidrs") == 0) {
            if (parse_region_cidrs(value, region) != 0) {
                fprintf(stderr, "Invalid region CIDR at %s:%d\n", context->canonical_path, line_no);
                return -1;
            }
            return 0;
        }
    }

    if (section->type == SECTION_ENDPOINT && endpoint != NULL) {
        if (strcmp(key, "name") == 0) {
            unquote_inplace(value);
            safe_copy(endpoint->name, sizeof(endpoint->name), value);
            return 0;
        }
        if (strcmp(key, "type") == 0) {
            EndpointType type = ENDPOINT_TYPE_NONE;
            unquote_inplace(value);
            type = parse_endpoint_type(value);
            if (type == ENDPOINT_TYPE_NONE) {
                fprintf(stderr, "Unsupported endpoint type at %s:%d: %s\n", context->canonical_path, line_no, value);
                return -1;
            }
            endpoint->type = type;
            endpoint->vless.enabled = type == ENDPOINT_TYPE_VLESS;
            endpoint->hysteria2.enabled = type == ENDPOINT_TYPE_HYSTERIA2;
            endpoint->shadowsocks.enabled = type == ENDPOINT_TYPE_SHADOWSOCKS;
            endpoint->shadowsocksr.enabled = type == ENDPOINT_TYPE_SHADOWSOCKSR;
            endpoint->vmess.enabled = type == ENDPOINT_TYPE_VMESS;
            endpoint->trojan.enabled = type == ENDPOINT_TYPE_TROJAN;
            endpoint->tuic.enabled = type == ENDPOINT_TYPE_TUIC;
            endpoint->anytls.enabled = type == ENDPOINT_TYPE_ANYTLS;
            return 0;
        }
        if (strcmp(key, "server") == 0) {
            unquote_inplace(value);
            safe_copy(endpoint->server, sizeof(endpoint->server), value);
            return 0;
        }
        if (strcmp(key, "port") == 0) {
            if (parse_port_value(value, &port_value) != 0) {
                fprintf(stderr, "Invalid endpoint.port at %s:%d\n", context->canonical_path, line_no);
                return -1;
            }
            endpoint->port = port_value;
            return 0;
        }
        if (strcmp(key, "udp") == 0) {
            if (parse_bool_value(value, &bool_value) != 0) {
                fprintf(stderr, "Invalid endpoint.udp at %s:%d\n", context->canonical_path, line_no);
                return -1;
            }
            endpoint->udp = bool_value != 0;
            return 0;
        }
        if (strcmp(key, "skip-cert-verify") == 0 || strcmp(key, "skip_cert_verify") == 0) {
            if (parse_bool_value(value, &bool_value) != 0) {
                fprintf(stderr, "Invalid endpoint.skip-cert-verify at %s:%d\n", context->canonical_path, line_no);
                return -1;
            }
            endpoint->skip_cert_verify = bool_value != 0;
            return 0;
        }
        if (strcmp(key, "uuid") == 0) {
            unquote_inplace(value);
            safe_copy(endpoint->vless.uuid, sizeof(endpoint->vless.uuid), value);
            safe_copy(endpoint->vmess.uuid, sizeof(endpoint->vmess.uuid), value);
            safe_copy(endpoint->tuic.uuid, sizeof(endpoint->tuic.uuid), value);
            return 0;
        }
        if (strcmp(key, "tls") == 0) {
            if (parse_bool_value(value, &bool_value) != 0) {
                fprintf(stderr, "Invalid endpoint.tls at %s:%d\n", context->canonical_path, line_no);
                return -1;
            }
            endpoint->vless.tls = bool_value != 0;
            endpoint->trojan.tls = bool_value != 0;
            endpoint->vmess.tls = bool_value != 0;
            endpoint->anytls.tls = bool_value != 0;
            return 0;
        }
        if (strcmp(key, "flow") == 0) {
            unquote_inplace(value);
            safe_copy(endpoint->vless.flow, sizeof(endpoint->vless.flow), value);
            return 0;
        }
        if (strcmp(key, "client-fingerprint") == 0 || strcmp(key, "client_fingerprint") == 0) {
            unquote_inplace(value);
            safe_copy(endpoint->vless.client_fingerprint, sizeof(endpoint->vless.client_fingerprint), value);
            safe_copy(endpoint->trojan.client_fingerprint, sizeof(endpoint->trojan.client_fingerprint), value);
            safe_copy(endpoint->vmess.client_fingerprint, sizeof(endpoint->vmess.client_fingerprint), value);
            safe_copy(endpoint->anytls.client_fingerprint, sizeof(endpoint->anytls.client_fingerprint), value);
            return 0;
        }
        if (strcmp(key, "servername") == 0) {
            unquote_inplace(value);
            safe_copy(endpoint->vless.servername, sizeof(endpoint->vless.servername), value);
            safe_copy(endpoint->trojan.servername, sizeof(endpoint->trojan.servername), value);
            safe_copy(endpoint->vmess.servername, sizeof(endpoint->vmess.servername), value);
            safe_copy(endpoint->anytls.servername, sizeof(endpoint->anytls.servername), value);
            return 0;
        }
        if (strcmp(key, "network") == 0) {
            unquote_inplace(value);
            safe_copy(endpoint->vless.network, sizeof(endpoint->vless.network), value);
            safe_copy(endpoint->trojan.network, sizeof(endpoint->trojan.network), value);
            safe_copy(endpoint->vmess.network, sizeof(endpoint->vmess.network), value);
            return 0;
        }
        if (strcmp(key, "password") == 0) {
            unquote_inplace(value);
            safe_copy(endpoint->hysteria2.password, sizeof(endpoint->hysteria2.password), value);
            safe_copy(endpoint->trojan.password, sizeof(endpoint->trojan.password), value);
            safe_copy(endpoint->shadowsocks.password, sizeof(endpoint->shadowsocks.password), value);
            safe_copy(endpoint->shadowsocksr.password, sizeof(endpoint->shadowsocksr.password), value);
            safe_copy(endpoint->tuic.password, sizeof(endpoint->tuic.password), value);
            safe_copy(endpoint->anytls.password, sizeof(endpoint->anytls.password), value);
            return 0;
        }
        if (strcmp(key, "sni") == 0) {
            unquote_inplace(value);
            safe_copy(endpoint->hysteria2.sni, sizeof(endpoint->hysteria2.sni), value);
            safe_copy(endpoint->tuic.sni, sizeof(endpoint->tuic.sni), value);
            return 0;
        }
        if (strcmp(key, "method") == 0) {
            unquote_inplace(value);
            safe_copy(endpoint->shadowsocks.method, sizeof(endpoint->shadowsocks.method), value);
            safe_copy(endpoint->shadowsocksr.method, sizeof(endpoint->shadowsocksr.method), value);
            return 0;
        }
        if (strcmp(key, "protocol") == 0) {
            unquote_inplace(value);
            safe_copy(endpoint->shadowsocksr.protocol, sizeof(endpoint->shadowsocksr.protocol), value);
            return 0;
        }
        if (strcmp(key, "protocol-param") == 0 || strcmp(key, "protocol_param") == 0) {
            unquote_inplace(value);
            safe_copy(endpoint->shadowsocksr.protocol_param, sizeof(endpoint->shadowsocksr.protocol_param), value);
            return 0;
        }
        if (strcmp(key, "obfs") == 0) {
            unquote_inplace(value);
            safe_copy(endpoint->shadowsocksr.obfs, sizeof(endpoint->shadowsocksr.obfs), value);
            return 0;
        }
        if (strcmp(key, "obfs-param") == 0 || strcmp(key, "obfs_param") == 0) {
            unquote_inplace(value);
            safe_copy(endpoint->shadowsocksr.obfs_param, sizeof(endpoint->shadowsocksr.obfs_param), value);
            return 0;
        }
        if (strcmp(key, "plugin") == 0) {
            unquote_inplace(value);
            safe_copy(endpoint->shadowsocks.plugin, sizeof(endpoint->shadowsocks.plugin), value);
            return 0;
        }
        if (strcmp(key, "alter-id") == 0 || strcmp(key, "alter_id") == 0) {
            endpoint->vmess.alter_id = atoi(value);
            return 0;
        }
        if (strcmp(key, "security") == 0 || strcmp(key, "cipher") == 0) {
            unquote_inplace(value);
            safe_copy(endpoint->vmess.security, sizeof(endpoint->vmess.security), value);
            return 0;
        }
        if (strcmp(key, "authenticated-length") == 0 || strcmp(key, "authenticated_length") == 0) {
            if (parse_bool_value(value, &bool_value) != 0) {
                fprintf(stderr, "Invalid endpoint.authenticated-length at %s:%d\n", context->canonical_path, line_no);
                return -1;
            }
            endpoint->vmess.authenticated_length = bool_value != 0;
            return 0;
        }
        if (strcmp(key, "congestion-control") == 0 || strcmp(key, "congestion_control") == 0) {
            unquote_inplace(value);
            safe_copy(endpoint->tuic.congestion_control, sizeof(endpoint->tuic.congestion_control), value);
            return 0;
        }
        if (strcmp(key, "udp-relay-mode") == 0 || strcmp(key, "udp_relay_mode") == 0) {
            unquote_inplace(value);
            safe_copy(endpoint->tuic.udp_relay_mode, sizeof(endpoint->tuic.udp_relay_mode), value);
            return 0;
        }
        if (strcmp(key, "zero-rtt") == 0 || strcmp(key, "zero_rtt") == 0) {
            if (parse_bool_value(value, &bool_value) != 0) {
                fprintf(stderr, "Invalid endpoint.zero-rtt at %s:%d\n", context->canonical_path, line_no);
                return -1;
            }
            endpoint->tuic.zero_rtt = bool_value != 0;
            return 0;
        }
        if (strcmp(key, "alpn") == 0) {
            unquote_inplace(value);
            safe_copy(endpoint->tuic.alpn, sizeof(endpoint->tuic.alpn), value);
            return 0;
        }
    }

    if (section->type == SECTION_ENDPOINT_WS_OPTS && endpoint != NULL) {
        if (strcmp(key, "path") == 0) {
            unquote_inplace(value);
            safe_copy(endpoint->vless.ws.path, sizeof(endpoint->vless.ws.path), value);
            safe_copy(endpoint->trojan.ws.path, sizeof(endpoint->trojan.ws.path), value);
            safe_copy(endpoint->vmess.ws.path, sizeof(endpoint->vmess.ws.path), value);
            return 0;
        }
        if (strcmp(key, "host") == 0 || strcmp(key, "Host") == 0) {
            unquote_inplace(value);
            safe_copy(endpoint->vless.ws.host, sizeof(endpoint->vless.ws.host), value);
            safe_copy(endpoint->trojan.ws.host, sizeof(endpoint->trojan.ws.host), value);
            safe_copy(endpoint->vmess.ws.host, sizeof(endpoint->vmess.ws.host), value);
            return 0;
        }
        if (strcmp(key, "headers") == 0) {
            if (parse_ws_headers(value, endpoint) != 0) {
                fprintf(stderr, "Invalid ws-opts.headers at %s:%d\n", context->canonical_path, line_no);
                return -1;
            }
            return 0;
        }
    }

    return 0;
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

static int uuid_is_valid(const char* uuid) {
    char compact[33];
    size_t compact_index = 0;
    size_t i = 0;

    for (i = 0; uuid[i] != '\0'; ++i) {
        if (uuid[i] == '-') {
            continue;
        }
        if (!isxdigit((unsigned char)uuid[i]) || compact_index >= sizeof(compact) - 1) {
            return 0;
        }
        compact[compact_index++] = uuid[i];
    }

    if (compact_index != 32) {
        return 0;
    }

    compact[compact_index] = '\0';
    for (i = 0; i < 16; ++i) {
        if (hex_value(compact[i * 2]) < 0 || hex_value(compact[i * 2 + 1]) < 0) {
            return 0;
        }
    }

    return 1;
}

static void endpoint_ref_string(const EndpointConfig* endpoint, char* out, size_t out_size) {
    if (endpoint->imported && endpoint->source_alias[0] != '\0') {
        const char* key_part = strchr(endpoint->key, ':');
        key_part = key_part != NULL ? key_part + 1 : endpoint->key;
        snprintf(out, out_size, "%s[%s]", endpoint->source_alias, key_part);
        return;
    }

    safe_copy(out, out_size, endpoint->key);
}

static int validate_endpoint(EndpointConfig* endpoint, char* error, size_t error_size) {
    char ref[ENDPOINT_NAME_LEN + ENDPOINT_NAME_LEN];

    if (error != NULL && error_size > 0) {
        error[0] = '\0';
    }

    endpoint_ref_string(endpoint, ref, sizeof(ref));

    if (endpoint->type == ENDPOINT_TYPE_VLESS) {
        if (endpoint->server[0] == '\0') {
            snprintf(error, error_size, "VLESS endpoint \"%s\" is missing server.", ref);
            return -1;
        }
        if (endpoint->vless.uuid[0] == '\0' || !uuid_is_valid(endpoint->vless.uuid)) {
            snprintf(error, error_size, "VLESS endpoint \"%s\" is missing a valid uuid.", ref);
            return -1;
        }
        if (endpoint->vless.flow[0] != '\0') {
            snprintf(error, error_size, "VLESS endpoint \"%s\" uses unsupported flow.", ref);
            return -1;
        }
        if (_stricmp(endpoint->vless.network, "ws") != 0 && _stricmp(endpoint->vless.network, "tcp") != 0) {
            snprintf(error, error_size, "VLESS endpoint \"%s\" must use network = \"ws\" or \"tcp\".", ref);
            return -1;
        }
        if (_stricmp(endpoint->vless.network, "ws") == 0 && endpoint->vless.ws.path[0] == '\0') {
            strcpy(endpoint->vless.ws.path, "/");
        }
        if (endpoint->vless.ws.host[0] == '\0') {
            if (endpoint->vless.servername[0] != '\0') {
                safe_copy(endpoint->vless.ws.host, sizeof(endpoint->vless.ws.host), endpoint->vless.servername);
            } else {
                safe_copy(endpoint->vless.ws.host, sizeof(endpoint->vless.ws.host), endpoint->server);
            }
        }
        if (endpoint->vless.servername[0] == '\0') {
            if (endpoint->vless.ws.host[0] != '\0') {
                safe_copy(endpoint->vless.servername, sizeof(endpoint->vless.servername), endpoint->vless.ws.host);
            } else {
                safe_copy(endpoint->vless.servername, sizeof(endpoint->vless.servername), endpoint->server);
            }
        }
        return 0;
    }

    if (endpoint->type == ENDPOINT_TYPE_HYSTERIA2) {
        if (endpoint->server[0] == '\0') {
            snprintf(error, error_size, "Hysteria2 endpoint \"%s\" is missing server.", ref);
            return -1;
        }
        if (endpoint->hysteria2.password[0] == '\0') {
            snprintf(error, error_size, "Hysteria2 endpoint \"%s\" is missing password.", ref);
            return -1;
        }
        if (endpoint->hysteria2.sni[0] == '\0') {
            safe_copy(endpoint->hysteria2.sni, sizeof(endpoint->hysteria2.sni), endpoint->server);
        }
        return 0;
    }

    if (endpoint->type == ENDPOINT_TYPE_TROJAN) {
        if (endpoint->server[0] == '\0') {
            snprintf(error, error_size, "Trojan endpoint \"%s\" is missing server.", ref);
            return -1;
        }
        if (endpoint->trojan.password[0] == '\0') {
            snprintf(error, error_size, "Trojan endpoint \"%s\" is missing password.", ref);
            return -1;
        }
        if (endpoint->trojan.servername[0] == '\0') {
            safe_copy(endpoint->trojan.servername, sizeof(endpoint->trojan.servername), endpoint->server);
        }
        if (endpoint->trojan.ws.host[0] == '\0') {
            safe_copy(endpoint->trojan.ws.host, sizeof(endpoint->trojan.ws.host), endpoint->trojan.servername);
        }
        return 0;
    }

    if (endpoint->type == ENDPOINT_TYPE_SHADOWSOCKS) {
        if (endpoint->server[0] == '\0' || endpoint->shadowsocks.password[0] == '\0' || endpoint->shadowsocks.method[0] == '\0') {
            snprintf(error, error_size, "Shadowsocks endpoint \"%s\" is missing server/method/password.", ref);
            return -1;
        }
        return 0;
    }

    if (endpoint->type == ENDPOINT_TYPE_SHADOWSOCKSR) {
        if (endpoint->server[0] == '\0' || endpoint->shadowsocksr.password[0] == '\0' || endpoint->shadowsocksr.method[0] == '\0') {
            snprintf(error, error_size, "SSR endpoint \"%s\" is missing server/method/password.", ref);
            return -1;
        }
        return 0;
    }

    if (endpoint->type == ENDPOINT_TYPE_VMESS) {
        if (endpoint->server[0] == '\0' || endpoint->vmess.uuid[0] == '\0' || !uuid_is_valid(endpoint->vmess.uuid)) {
            snprintf(error, error_size, "VMess endpoint \"%s\" is missing server or valid uuid.", ref);
            return -1;
        }
        if (endpoint->vmess.servername[0] == '\0') {
            safe_copy(endpoint->vmess.servername, sizeof(endpoint->vmess.servername), endpoint->server);
        }
        if (endpoint->vmess.ws.host[0] == '\0') {
            safe_copy(endpoint->vmess.ws.host, sizeof(endpoint->vmess.ws.host), endpoint->vmess.servername);
        }
        return 0;
    }

    if (endpoint->type == ENDPOINT_TYPE_TUIC) {
        if (endpoint->server[0] == '\0' || endpoint->tuic.uuid[0] == '\0' || endpoint->tuic.password[0] == '\0') {
            snprintf(error, error_size, "TUIC endpoint \"%s\" is missing server/uuid/password.", ref);
            return -1;
        }
        if (endpoint->tuic.sni[0] == '\0') {
            safe_copy(endpoint->tuic.sni, sizeof(endpoint->tuic.sni), endpoint->server);
        }
        return 0;
    }

    if (endpoint->type == ENDPOINT_TYPE_ANYTLS) {
        if (endpoint->server[0] == '\0' || endpoint->anytls.password[0] == '\0') {
            snprintf(error, error_size, "AnyTLS endpoint \"%s\" is missing server/password.", ref);
            return -1;
        }
        if (endpoint->anytls.servername[0] == '\0') {
            safe_copy(endpoint->anytls.servername, sizeof(endpoint->anytls.servername), endpoint->server);
        }
        return 0;
    }

    snprintf(error, error_size, "Endpoint \"%s\" has unsupported type.", ref);
    return -1;
}

static int validate_rules(const Config* config) {
    int i = 0;

    for (i = 0; i < config->rule_count; ++i) {
        const RouteRule* rule = &config->rules[i];

        if (rule->action == ROUTE_ACTION_NONE) {
            fprintf(stderr, "Rule \"%s\" has no action.\n", rule->name);
            return -1;
        }

        if (rule->region[0] != '\0' && rule->region_db[0] == '\0' &&
            find_region((Config*)config, rule->region) == NULL) {
            fprintf(stderr, "Rule \"%s\" references unknown region \"%s\".\n", rule->name, rule->region);
            return -1;
        }
        if (rule->region_db[0] != '\0' && config->country_db_path[0] == '\0') {
            fprintf(stderr, "Rule \"%s\" uses region-db but no country-db is configured in [main].\n", rule->name);
            return -1;
        }

        if (rule->action == ROUTE_ACTION_PROXY && rule->endpoint[0] != '\0' &&
            find_endpoint_by_name(config, rule->endpoint) == NULL) {
            fprintf(stderr, "Rule \"%s\" references unknown endpoint \"%s\".\n", rule->name, rule->endpoint);
            return -1;
        }
    }

    return 0;
}

static int load_config_file(const char* filename, const char* alias, int is_root, Config* config, LoadState* state) {
    FILE* fp = NULL;
    char canonical_path[CONFIG_PATH_LEN];
    char line[MAX_LINE_LEN];
    ParseSection section;
    ParseContext context;
    int line_no = 0;

    if (canonicalize_path(filename, canonical_path, sizeof(canonical_path)) != 0) {
        FILE* probe = fopen(filename, "rb");
        if (probe == NULL) {
            fprintf(stderr, "Failed to open config: %s\n", filename);
            return -1;
        }
        fclose(probe);
    }

    if (load_state_contains(state, canonical_path)) {
        return 0;
    }
    if (load_state_add(state, canonical_path) != 0) {
        fprintf(stderr, "Too many nested config imports.\n");
        return -1;
    }

    fp = fopen(canonical_path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open config: %s\n", canonical_path);
        return -1;
    }

    memset(&context, 0, sizeof(context));
    context.config = config;
    context.state = state;
    context.canonical_path = canonical_path;
    context.is_root = is_root;
    path_dirname(canonical_path, context.directory, sizeof(context.directory));

    if (!is_root) {
        if (alias != NULL && alias[0] != '\0') {
            safe_copy(context.import_alias, sizeof(context.import_alias), alias);
        } else {
            path_stem_from_basename(path_basename_ptr(canonical_path), context.import_alias, sizeof(context.import_alias));
        }
    }

    section.type = SECTION_NONE;
    section.endpoint = NULL;
    section.rule = NULL;
    section.region = NULL;

    while (fgets(line, sizeof(line), fp) != NULL) {
        char* equals = NULL;
        char* key = NULL;
        char* value = NULL;

        ++line_no;
        strip_comment(line);
        trim_inplace(line);

        if (line[0] == '\0') {
            continue;
        }

        if (line[0] == '[') {
            if (parse_section_header(&context, line, &section) != 0) {
                fprintf(stderr, "Invalid section header at %s:%d\n", canonical_path, line_no);
                fclose(fp);
                return -1;
            }
            continue;
        }

        equals = strchr(line, '=');
        if (equals == NULL) {
            fprintf(stderr, "Invalid config line at %s:%d: %s\n", canonical_path, line_no, line);
            fclose(fp);
            return -1;
        }

        *equals = '\0';
        key = line;
        value = equals + 1;
        trim_inplace(key);
        trim_inplace(value);

        if (parse_config_entry(&context, &section, key, value, line_no) != 0) {
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    return 0;
}

void cleanup_config(Config* config) {
    if (!config) return;
    mmdb_close((mmdb*)config->country_db_handle);
    config->country_db_handle = NULL;
}

const EndpointConfig* get_active_endpoint(const Config* config) {
    if (config->active_endpoint[0] == '\0') {
        return config->endpoint_count == 1 ? &config->endpoints[0] : NULL;
    }

    return find_endpoint_by_name(config, config->active_endpoint);
}

int load_config(const char* filename, Config* config) {
    LoadState state;
    char error[256];
    int i = 0;

    memset(&state, 0, sizeof(state));
    set_config_defaults(config);

    if (load_config_file(filename, NULL, 1, config, &state) != 0) {
        return -1;
    }

    if (config->country_db_path[0] != '\0') {
        mmdb* db = NULL;
        if (mmdb_open(config->country_db_path, &db) != 0) {
            fprintf(stderr, "Failed to open country database: %s\n", config->country_db_path);
            return -1;
        }
        config->country_db_handle = db;
    }

    if (config->endpoint_count == 0) {
        fprintf(stderr, "No endpoints configured.\n");
        return -1;
    }

    if (config->active_endpoint[0] == '\0' && config->endpoint_count == 1) {
        safe_copy(config->active_endpoint, sizeof(config->active_endpoint), config->endpoints[0].key);
    }

    for (i = 0; i < config->endpoint_count; ++i) {
        if (validate_endpoint(&config->endpoints[i], error, sizeof(error)) != 0) {
            if (config->endpoints[i].imported) {
                config->endpoints[i].enabled = false;
                fprintf(stderr, "Skipping imported endpoint: %s\n", error);
                continue;
            }
            fprintf(stderr, "%s\n", error);
            return -1;
        }
    }

    for (i = 0; i < config->region_count; ++i) {
        if (config->regions[i].cidr_count == 0) {
            fprintf(stderr, "Region \"%s\" has no CIDRs.\n", config->regions[i].name);
            return -1;
        }
    }

    if (validate_rules(config) != 0) {
        return -1;
    }

    if (get_active_endpoint(config) == NULL) {
        const EndpointConfig* disabled_endpoint = find_endpoint_by_name_internal(config, config->active_endpoint, 1);
        if (disabled_endpoint != NULL && !disabled_endpoint->enabled) {
            fprintf(stderr, "Configured main.endpoint \"%s\" is unsupported in this build.\n", config->active_endpoint);
            return -1;
        }
        fprintf(stderr, "Configured main.endpoint \"%s\" does not exist.\n", config->active_endpoint);
        return -1;
    }

    return 0;
}

static int domain_equals_or_subdomain(const char* domain, const char* suffix) {
    size_t domain_len = strlen(domain);
    size_t suffix_len = strlen(suffix);

    if (domain_len < suffix_len) {
        return 0;
    }

    if (_stricmp(domain + domain_len - suffix_len, suffix) != 0) {
        return 0;
    }

    if (domain_len == suffix_len) {
        return 1;
    }

    return domain[domain_len - suffix_len - 1] == '.';
}

static int rule_matches_domain(const RouteRule* rule, const char* domain) {
    int i = 0;
    int has_matchers = 0;

    for (i = 0; i < rule->domain_count; ++i) {
        const char* pattern = rule->domains[i];
        if (pattern[0] == '\0') {
            continue;
        }
        has_matchers = 1;
        if (starts_with_ci(pattern, "*.")) {
            if (domain_equals_or_subdomain(domain, pattern + 2)) {
                return 1;
            }
        } else if (string_equals_ci(domain, pattern)) {
            return 1;
        }
    }

    if (!has_matchers) {
        return 1;
    }

    if (domain == NULL || domain[0] == '\0') {
        return 0;
    }

    for (i = 0; i < rule->domain_suffix_count; ++i) {
        if (rule->domain_suffixes[i][0] == '\0') {
            continue;
        }
        if (domain_equals_or_subdomain(domain, rule->domain_suffixes[i])) {
            return 1;
        }
    }

    for (i = 0; i < rule->domain_keyword_count; ++i) {
        if (rule->domain_keywords[i][0] == '\0') {
            continue;
        }
        if (string_contains_ci(domain, rule->domain_keywords[i])) {
            return 1;
        }
    }

    return 0;
}

static int cidr_matches_ip(const RegionCidr* cidr, int family, const unsigned char* addr) {
    int full_bytes = 0;
    int remaining_bits = 0;
    int bytes_to_check = family == AF_INET ? 4 : 16;

    if (cidr->family != family) {
        return 0;
    }

    full_bytes = cidr->prefix_len / 8;
    remaining_bits = cidr->prefix_len % 8;

    if (full_bytes > 0 && memcmp(cidr->addr, addr, (size_t)full_bytes) != 0) {
        return 0;
    }

    if (remaining_bits > 0 && full_bytes < bytes_to_check) {
        unsigned char mask = (unsigned char)(0xFFu << (8 - remaining_bits));
        if ((cidr->addr[full_bytes] & mask) != (addr[full_bytes] & mask)) {
            return 0;
        }
    }

    return 1;
}

static int destination_collect_ips(const Destination* destination, int families[], unsigned char addrs[][16], int max_count) {
    int count = 0;

    if (destination->type == DEST_ADDR_IPV4) {
        if (max_count < 1) {
            return 0;
        }
        families[0] = AF_INET;
        memcpy(addrs[0], destination->raw_addr, 4);
        return 1;
    }

    if (destination->type == DEST_ADDR_IPV6) {
        if (max_count < 1) {
            return 0;
        }
        families[0] = AF_INET6;
        memcpy(addrs[0], destination->raw_addr, 16);
        return 1;
    }

    if (destination->type == DEST_ADDR_DOMAIN) {
        struct addrinfo hints;
        struct addrinfo* result = NULL;
        struct addrinfo* item = NULL;
        char port_text[16];

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        snprintf(port_text, sizeof(port_text), "%u", (unsigned int)destination->port);
        if (getaddrinfo(destination->host, port_text, &hints, &result) != 0) {
            return 0;
        }

        for (item = result; item != NULL && count < max_count; item = item->ai_next) {
            if (item->ai_family == AF_INET) {
                struct sockaddr_in* addr4 = (struct sockaddr_in*)item->ai_addr;
                families[count] = AF_INET;
                memcpy(addrs[count], &addr4->sin_addr, 4);
                ++count;
            } else if (item->ai_family == AF_INET6) {
                struct sockaddr_in6* addr6 = (struct sockaddr_in6*)item->ai_addr;
                families[count] = AF_INET6;
                memcpy(addrs[count], &addr6->sin6_addr, 16);
                ++count;
            }
        }

        freeaddrinfo(result);
    }

    return count;
}

static int ip_matches_region_db(const Config* config, const char* region_code,
                                 int family, const unsigned char* addr) {
    mmdb* db = (mmdb*)config->country_db_handle;
    char code[8];
    if (!db) return 0;
    if (mmdb_lookup_country_code(db, family, addr, code, sizeof(code)) != 0)
        return 0;
    return _stricmp(code, region_code) == 0;
}

static int rule_matches_region(const Config* config, const RouteRule* rule,
                                const Destination* destination) {
    int families[16];
    unsigned char addrs[16][16];
    int addr_count = 0;
    int i = 0;
    int j = 0;
    const RegionConfig* region = NULL;

    /* No region or region-db → no IP restriction */
    if (rule->region[0] == '\0' && rule->region_db[0] == '\0') {
        return 1;
    }

    if (destination->type == DEST_ADDR_DOMAIN && !rule->resolve) {
        return 0;
    }

    addr_count = destination_collect_ips(destination, families, addrs, 16);
    if (addr_count <= 0) {
        return 0;
    }

    /* region-db: mmdb-based country code lookup */
    if (rule->region_db[0] != '\0') {
        for (i = 0; i < addr_count; ++i) {
            if (ip_matches_region_db(config, rule->region_db, families[i], addrs[i]))
                return 1;
        }
        return 0;
    }

    /* static CIDR-based region matching */
    region = find_region((Config*)config, rule->region);
    if (region == NULL) {
        return 0;
    }

    for (i = 0; i < addr_count; ++i) {
        for (j = 0; j < region->cidr_count; ++j) {
            if (cidr_matches_ip(&region->cidrs[j], families[i], addrs[i])) {
                return 1;
            }
        }
    }

    return 0;
}

int resolve_route(const Config* config, const Destination* destination, RouteDecision* decision) {
    int i = 0;
    const char* domain = destination->type == DEST_ADDR_DOMAIN ? destination->host : NULL;

    memset(decision, 0, sizeof(*decision));

    for (i = 0; i < config->rule_count; ++i) {
        const RouteRule* rule = &config->rules[i];

        if (!rule_matches_domain(rule, domain)) {
            continue;
        }

        if (!rule_matches_region(config, rule, destination)) {
            continue;
        }

        decision->action = rule->action;
        decision->rule = rule;
        if (rule->action == ROUTE_ACTION_PROXY) {
            decision->endpoint = rule->endpoint[0] != '\0' ? find_endpoint_by_name(config, rule->endpoint) : get_active_endpoint(config);
            if (decision->endpoint == NULL) {
                return -1;
            }
        }
        return 0;
    }

    decision->action = ROUTE_ACTION_PROXY;
    decision->endpoint = get_active_endpoint(config);
    if (decision->endpoint == NULL) {
        return -1;
    }
    decision->rule = NULL;
    return 0;
}
