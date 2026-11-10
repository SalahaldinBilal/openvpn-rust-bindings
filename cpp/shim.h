#ifndef OVPN_SHIM_H
#define OVPN_SHIM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Strings passed in either direction are only valid for the duration of the call. */
typedef struct ovpn_shim_str {
    const char *ptr;
    size_t len;
} ovpn_shim_str;

typedef struct ovpn_shim ovpn_shim;

typedef void (*ovpn_shim_reply_fn)(void *reply_ctx, ovpn_shim_str value, ovpn_shim_str error);

typedef struct ovpn_shim_callbacks {
    void *ctx;
    void (*event)(void *ctx, int32_t error, int32_t fatal, ovpn_shim_str name, ovpn_shim_str info);
    void (*log)(void *ctx, ovpn_shim_str text);
    /* Must call reply exactly once before returning, with a base64 signature or an error. */
    void (*pki_sign)(void *ctx, ovpn_shim_str data_b64, ovpn_shim_str algorithm, ovpn_shim_str hashalg, ovpn_shim_str saltlen, void *reply_ctx, ovpn_shim_reply_fn reply);
    /* The tunnel's settings as "key value" lines: addr4, addr6, gw4, gw6, route4, route6, dns, domain (search), split (names to resolve through the VPN's DNS), mtu. */
    void (*tun_up)(void *ctx, ovpn_shim_str settings);
    /* One IP packet from Core. Returns 0 when it was dropped. */
    int32_t (*tun_send)(void *ctx, const uint8_t *data, size_t len);
    void (*tun_down)(void *ctx);
} ovpn_shim_callbacks;

typedef struct ovpn_shim_config {
    ovpn_shim_str profile;
    /* PEM. An empty cert means the profile has no client certificate. */
    ovpn_shim_str cert;
    ovpn_shim_str chain;
    ovpn_shim_str gui_version;
    int32_t conn_timeout_secs;
    int32_t compression;
    int32_t allow_non_preferred_ciphers;
    int32_t tls_version_min;
} ovpn_shim_config;

/* Values of ovpn_shim_config.compression. */
#define OVPN_SHIM_COMPRESSION_OFF 0
#define OVPN_SHIM_COMPRESSION_DOWNLINK 1
#define OVPN_SHIM_COMPRESSION_BOTH 2

/* Values of ovpn_shim_config.tls_version_min. A profile's higher tls-version-min still wins. */
#define OVPN_SHIM_TLS_MIN_FROM_PROFILE 0
#define OVPN_SHIM_TLS_MIN_1_2 1
#define OVPN_SHIM_TLS_MIN_1_3 2

typedef struct ovpn_shim_eval {
    int32_t error;
    ovpn_shim_str message;
    int32_t autologin;
    int32_t external_pki;
    ovpn_shim_str static_challenge;
    int32_t static_challenge_echo;
    ovpn_shim_str remote_host;
    ovpn_shim_str remote_port;
    ovpn_shim_str remote_proto;
} ovpn_shim_eval;

typedef struct ovpn_shim_status {
    int32_t error;
    ovpn_shim_str status;
    ovpn_shim_str message;
} ovpn_shim_status;

typedef struct ovpn_shim_stats {
    int64_t bytes_in;
    int64_t bytes_out;
    int64_t packets_in;
    int64_t packets_out;
    int32_t last_packet_received;
} ovpn_shim_stats;

typedef struct ovpn_shim_challenge {
    ovpn_shim_str challenge;
    int32_t echo;
    int32_t response_required;
    ovpn_shim_str state_id;
} ovpn_shim_challenge;

typedef void (*ovpn_shim_eval_fn)(void *out_ctx, const ovpn_shim_eval *eval);
typedef void (*ovpn_shim_status_fn)(void *out_ctx, const ovpn_shim_status *status);
typedef void (*ovpn_shim_challenge_fn)(void *out_ctx, const ovpn_shim_challenge *challenge);

/* Process-wide setup. Call once before the first client and keep it for the life of the process. */
int32_t ovpn_shim_init_process(void);

ovpn_shim *ovpn_shim_new(const ovpn_shim_callbacks *callbacks);
void ovpn_shim_free(ovpn_shim *client);

/* Each returns 0 when an exception escaped Core, after reporting it through the out callback. */
int32_t ovpn_shim_eval_config(ovpn_shim *client, const ovpn_shim_config *config, void *out_ctx, ovpn_shim_eval_fn out);
int32_t ovpn_shim_provide_creds(ovpn_shim *client, ovpn_shim_str username, ovpn_shim_str password, ovpn_shim_str response, ovpn_shim_str dynamic_cookie, void *out_ctx, ovpn_shim_status_fn out);
/* Blocks until the session ends. */
int32_t ovpn_shim_connect(ovpn_shim *client, void *out_ctx, ovpn_shim_status_fn out);

/* Safe to call from any thread while ovpn_shim_connect runs. */
void ovpn_shim_stop(ovpn_shim *client);
void ovpn_shim_pause(ovpn_shim *client, ovpn_shim_str reason);
void ovpn_shim_resume(ovpn_shim *client);
void ovpn_shim_reconnect(ovpn_shim *client, int32_t seconds);
void ovpn_shim_transport_stats(ovpn_shim *client, ovpn_shim_stats *out);

/* Hands one IP packet to Core. Returns 0 when there's no tunnel up to take it. Any thread. */
int32_t ovpn_shim_tun_recv(ovpn_shim *client, const uint8_t *data, size_t len);

int32_t ovpn_shim_parse_dynamic_challenge(ovpn_shim_str cookie, void *out_ctx, ovpn_shim_challenge_fn out);

#ifdef __cplusplus
}
#endif

#endif
