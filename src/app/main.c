#include <stdio.h>
#include <string.h>
#include "core/platform.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "core/pulse.h"

static const char* resolve_default_config_path(void) {
    static const char* candidates[] = {
        "config/config.toml",
        "../config/config.toml",
    };
    FILE* fp = NULL;
    size_t i = 0;

    for (i = 0; i < sizeof(candidates) / sizeof(candidates[0]); ++i) {
        fp = fopen(candidates[i], "rb");
        if (fp != NULL) {
            fclose(fp);
            return candidates[i];
        }
    }

    return candidates[0];
}

static void print_usage(const char* argv0) {
    printf("Usage:\n");
    printf("  %s run [config.toml]\n", argv0);
    printf("  %s sub <url> [--proxy] [--proxy host:port]\n", argv0);
}

static int run_proxy_command(const char* config_path) {
    Config* config = NULL;
    const EndpointConfig* endpoint = NULL;
    int result = 1;

    config = (Config*)calloc(1, sizeof(*config));
    if (config == NULL) {
        fprintf(stderr, "Failed to allocate config state.\n");
        return 1;
    }

    if (load_config(config_path, config) != 0) {
        fprintf(stderr, "Failed to load config: %s\n", config_path);
        goto cleanup;
    }

    endpoint = get_active_endpoint(config);
    if (endpoint == NULL) {
        fprintf(stderr, "No active endpoint selected.\n");
        goto cleanup;
    }

    printf("Loaded config: %s\n", config_path);
    printf("Inbound: %s://%s:%d\n", inbound_type_name(config->type), config->local_bind_addr, config->local_port);
    printf("Active endpoint: %s (%s)\n", endpoint->key, endpoint->name);
    printf("Outbound: %s://%s:%d\n", endpoint_type_name(endpoint->type), endpoint->server, endpoint->port);

    if (endpoint->type == ENDPOINT_TYPE_VLESS) {
        printf("Transport: %s%s\n",
            endpoint->vless.network,
            endpoint->vless.tls ? "+tls" : "");
        if (endpoint->vless.client_fingerprint[0] != '\0') {
            printf("Note: client-fingerprint=\"%s\" is parsed but not emulated; OpenSSL defaults are used.\n",
                endpoint->vless.client_fingerprint);
        }
    } else if (endpoint->type == ENDPOINT_TYPE_HYSTERIA2) {
        printf("Transport: quic+h3\n");
#if !defined(PULSE_HAVE_HYSTERIA2)
        printf("Note: this Linux build currently disables Hysteria2 runtime support.\n");
#endif
    } else if (endpoint->type == ENDPOINT_TYPE_TROJAN) {
        printf("Transport: %s%s\n",
            endpoint->trojan.network,
            endpoint->trojan.tls ? "+tls" : "");
    } else if (endpoint->type == ENDPOINT_TYPE_SHADOWSOCKS) {
        printf("Cipher: %s\n", endpoint->shadowsocks.method);
    } else if (endpoint->type == ENDPOINT_TYPE_SHADOWSOCKSR) {
        printf("Cipher: %s, protocol: %s, obfs: %s\n",
            endpoint->shadowsocksr.method,
            endpoint->shadowsocksr.protocol,
            endpoint->shadowsocksr.obfs);
    } else if (endpoint->type == ENDPOINT_TYPE_VMESS) {
        printf("Transport: %s%s\n",
            endpoint->vmess.network,
            endpoint->vmess.tls ? "+tls" : "");
    } else if (endpoint->type == ENDPOINT_TYPE_TUIC) {
        printf("Transport: quic\n");
    } else if (endpoint->type == ENDPOINT_TYPE_ANYTLS) {
        printf("Transport: tls\n");
    }

    if (endpoint->udp) {
        printf("Note: endpoint enables UDP, but this build currently proxies TCP only.\n");
    }

    if (config->rule_count > 0) {
        printf("Rules: %d\n", config->rule_count);
    }

    fflush(stdout);
    fflush(stderr);

    if (start_proxy(config) != 0) {
        fprintf(stderr, "Proxy stopped with an error.\n");
        goto cleanup;
    }

    result = 0;

cleanup:
    free(config);
    return result;
}

static int handle_run_command(int argc, char** argv) {
    const char* config_path = argc >= 3 ? argv[2] : resolve_default_config_path();
    return run_proxy_command(config_path);
}

static int handle_sub_command(int argc, char** argv) {
    const char* url = NULL;
    const char* proxy_spec = NULL;
    int i = 0;

    if (argc < 3) {
        fprintf(stderr, "Missing subscription URL.\n");
        return 1;
    }

    url = argv[2];
    for (i = 3; i < argc; ++i) {
        if (strcmp(argv[i], "--proxy") == 0) {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                proxy_spec = argv[i + 1];
                ++i;
            } else {
                proxy_spec = "";
            }
            continue;
        }

        fprintf(stderr, "Unknown argument: %s\n", argv[i]);
        return 1;
    }

    return download_subscription_command(url, proxy_spec);
}

int main(int argc, char** argv) {
    int exit_code = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    if (platform_init_network() != 0) {
        fprintf(stderr, "Network initialization failed: %d\n", WSAGetLastError());
        return 1;
    }

    OPENSSL_init_ssl(0, NULL);
    ERR_clear_error();

    if (argc < 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_usage(argv[0]);
        platform_cleanup_network();
        return argc < 2 ? 1 : 0;
    }

    if (strcmp(argv[1], "run") == 0) {
        exit_code = handle_run_command(argc, argv);
    } else if (strcmp(argv[1], "sub") == 0) {
        exit_code = handle_sub_command(argc, argv);
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        print_usage(argv[0]);
        exit_code = 1;
    }

    platform_cleanup_network();
    return exit_code;
}
