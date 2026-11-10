// Core compiles inside this file, like Core's own test client, so defines here apply to all of it.
#define OPENVPN_CORE_API_VISIBILITY_HIDDEN

#include <client/ovpncli.cpp>

#include <openvpn/client/rgopt.hpp>
#include <openvpn/tun/extern/config.hpp>
#include <openvpn/tun/client/tunbase.hpp>
#include <openvpn/tun/client/tunprop.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/log/sessionstats.hpp>

#include <memory>
#include <mutex>
#include <string>

#include <openssl/crypto.h>

#include "shim.h"

namespace {

const char *const PKI_ALIAS = "client";

std::string to_string(ovpn_shim_str value)
{
    if (value.ptr == nullptr || value.len == 0)
        return std::string();
    return std::string(value.ptr, value.len);
}

// Overwrites a secret before its memory is freed. OPENSSL_cleanse isn't optimised away like a plain memset.
void wipe(std::string &value)
{
    if (!value.empty())
        OPENSSL_cleanse(value.data(), value.size());
    value.clear();
}

// The profile can carry a tls-auth or tls-crypt key inline.
struct WipeOnExit
{
    std::string &value;

    ~WipeOnExit()
    {
        wipe(value);
    }
};

// The copies this file makes of a login. Core keeps its own while the session needs them.
struct CredsGuard
{
    openvpn::ClientAPI::ProvideCreds &creds;

    ~CredsGuard()
    {
        wipe(creds.password);
        wipe(creds.response);
        wipe(creds.dynamicChallengeCookie);
    }
};

ovpn_shim_str view(const std::string &value)
{
    return ovpn_shim_str{value.data(), value.size()};
}

const ovpn_shim_str empty_str{nullptr, 0};

// Records what Core would set on a real adapter. A userspace tunnel only needs the addresses and DNS, the rest is for
// callers that set up an adapter themselves.
class SettingsBuilder final : public openvpn::TunBuilderBase
{
  public:
    std::string lines;

    bool tun_builder_new() override
    {
        lines.clear();
        return true;
    }

    bool tun_builder_set_remote_address(const std::string &address, bool) override
    {
        add_line("remote", address);
        return true;
    }

    bool tun_builder_add_address(const std::string &address, int prefix_length, const std::string &gateway, bool ipv6, bool) override
    {
        add_line(ipv6 ? "addr6" : "addr4", address + "/" + std::to_string(prefix_length));
        if (!gateway.empty())
            add_line(ipv6 ? "gw6" : "gw4", gateway);
        return true;
    }

    bool tun_builder_set_route_metric_default(int metric) override
    {
        add_line("metric", std::to_string(metric));
        return true;
    }

    bool tun_builder_reroute_gw(bool ipv4, bool ipv6, unsigned int flags) override
    {
        if (ipv4)
            add_line("redirect4");
        if (ipv6)
            add_line("redirect6");
        if ((ipv4 || ipv6) && (flags & openvpn::RedirectGatewayFlags::RG_DEF1) != 0)
            add_line("def1");
        return true;
    }

    bool tun_builder_add_route(const std::string &address, int prefix_length, int metric, bool ipv6) override
    {
        add_line(ipv6 ? "route6" : "route4", network(address, prefix_length, metric));
        return true;
    }

    bool tun_builder_exclude_route(const std::string &address, int prefix_length, int metric, bool ipv6) override
    {
        add_line(ipv6 ? "exclude6" : "exclude4", network(address, prefix_length, metric));
        return true;
    }

    bool tun_builder_set_allow_family(int af, bool allow) override
    {
        if (!allow && af == AF_INET)
            add_line("block4");
        if (!allow && af == AF_INET6)
            add_line("block6");
        return true;
    }

    bool tun_builder_set_dns_options(const openvpn::DnsOptions &dns) override
    {
        for (const auto &entry : dns.servers)
        {
            for (const auto &address : entry.second.addresses)
            {
                std::string value = address.address;
                if (address.port != 0)
                    value += " " + std::to_string(address.port);
                add_line("dns", value);
            }
            for (const auto &domain : entry.second.domains)
                add_line("split", domain.domain);
        }
        for (const auto &domain : dns.search_domains)
            add_line("domain", domain.domain);
        return true;
    }

    bool tun_builder_set_mtu(int mtu) override
    {
        add_line("mtu", std::to_string(mtu));
        return true;
    }

    bool tun_builder_set_session_name(const std::string &) override
    {
        return true;
    }

    bool tun_builder_add_proxy_bypass(const std::string &) override
    {
        return true;
    }

    bool tun_builder_set_proxy_auto_config_url(const std::string &) override
    {
        return true;
    }

    bool tun_builder_set_proxy_http(const std::string &, int) override
    {
        return true;
    }

    bool tun_builder_set_proxy_https(const std::string &, int) override
    {
        return true;
    }

    bool tun_builder_add_wins_server(const std::string &) override
    {
        return true;
    }

  private:
    // Core passes -1 for a route without a metric of its own.
    static std::string network(const std::string &address, int prefix_length, int metric)
    {
        std::string value = address + "/" + std::to_string(prefix_length);
        if (metric >= 0)
            value += " " + std::to_string(metric);
        return value;
    }

    void add_line(const char *key)
    {
        lines += key;
        lines += '\n';
    }

    void add_line(const char *key, const std::string &value)
    {
        lines += key;
        lines += ' ';
        lines += value;
        lines += '\n';
    }
};

// Shared between the client, the current tunnel and packets arriving from Rust on other threads.
struct TunLink
{
    std::mutex mutex;
    openvpn_io::io_context *io = nullptr;
    openvpn::TunClientParent *parent = nullptr;
    openvpn::Frame::Ptr frame;
    openvpn::SessionStats::Ptr stats;
};

class ShimTunFactory;

class ShimTun final : public openvpn::TunClient
{
  public:
    ShimTun(openvpn_io::io_context &io, openvpn::TunClientParent &parent, ShimTunFactory *factory);
    ~ShimTun() override;

    void tun_start(const openvpn::OptionList &opt, openvpn::TransportClient &transcli, openvpn::CryptoDCSettings &) override;
    void stop() override;

    void set_disconnect() override
    {
    }

    bool tun_send(openvpn::BufferAllocated &buf) override;

    std::string tun_name() const override
    {
        return "userspace";
    }

    std::string vpn_ip4() const override
    {
        return state_->vpn_ip4_addr.specified() ? state_->vpn_ip4_addr.to_string() : std::string();
    }

    std::string vpn_ip6() const override
    {
        return state_->vpn_ip6_addr.specified() ? state_->vpn_ip6_addr.to_string() : std::string();
    }

    std::string vpn_gw4() const override
    {
        return state_->vpn_ip4_gw.specified() ? state_->vpn_ip4_gw.to_string() : std::string();
    }

    std::string vpn_gw6() const override
    {
        return state_->vpn_ip6_gw.specified() ? state_->vpn_ip6_gw.to_string() : std::string();
    }

    int vpn_mtu() const override
    {
        return state_->mtu;
    }

    void apply_push_update(const openvpn::OptionList &opt, openvpn::TransportClient &transcli) override;

  private:
    void detach();

    openvpn_io::io_context &io_;
    openvpn::TunClientParent &parent_;
    openvpn::RCPtr<ShimTunFactory> factory_;
    openvpn::TunProp::State::Ptr state_;
    bool up_ = false;
};

class ShimTunFactory final : public openvpn::TunClientFactory
{
  public:
    ShimTunFactory(const ovpn_shim_callbacks &callbacks, std::shared_ptr<TunLink> link, const openvpn::ExternalTun::Config &config)
        : callbacks(callbacks), link(std::move(link)), tun_prop(config.tun_prop), frame(config.frame), stats(config.stats)
    {
    }

    openvpn::TunClient::Ptr new_tun_client_obj(openvpn_io::io_context &io, openvpn::TunClientParent &parent, openvpn::TransportClient *) override
    {
        return openvpn::TunClient::Ptr(new ShimTun(io, parent, this));
    }

    bool supports_epoch_data() override
    {
        return true;
    }

    ovpn_shim_callbacks callbacks;
    std::shared_ptr<TunLink> link;
    openvpn::TunProp::Config tun_prop;
    openvpn::Frame::Ptr frame;
    openvpn::SessionStats::Ptr stats;
};

ShimTun::ShimTun(openvpn_io::io_context &io, openvpn::TunClientParent &parent, ShimTunFactory *factory)
    : io_(io), parent_(parent), factory_(factory), state_(new openvpn::TunProp::State())
{
}

ShimTun::~ShimTun()
{
    stop();
}

void ShimTun::tun_start(const openvpn::OptionList &opt, openvpn::TransportClient &transcli, openvpn::CryptoDCSettings &)
{
    if (up_)
        return;
    try
    {
        SettingsBuilder builder;
        builder.tun_builder_new();
        parent_.tun_pre_tun_config();
        openvpn::TunProp::configure_builder(&builder,
                                            state_.get(),
                                            factory_->stats.get(),
                                            transcli.server_endpoint_addr(),
                                            factory_->tun_prop,
                                            opt,
                                            nullptr,
                                            false);
        {
            std::lock_guard<std::mutex> lock(factory_->link->mutex);
            factory_->link->io = &io_;
            factory_->link->parent = &parent_;
            factory_->link->frame = factory_->frame;
            factory_->link->stats = factory_->stats;
        }
        up_ = true;
        const auto &callbacks = factory_->callbacks;
        if (callbacks.tun_up != nullptr)
            callbacks.tun_up(callbacks.ctx, view(builder.lines));
        // Packets from Rust are posted to this io_context from other threads, so none can run before this returns.
        parent_.tun_connected();
    }
    catch (const std::exception &error)
    {
        stop();
        parent_.tun_error(openvpn::Error::TUN_SETUP_FAILED, error.what());
    }
}

void ShimTun::stop()
{
    detach();
    if (up_)
    {
        up_ = false;
        const auto &callbacks = factory_->callbacks;
        if (callbacks.tun_down != nullptr)
            callbacks.tun_down(callbacks.ctx);
    }
}

void ShimTun::detach()
{
    std::lock_guard<std::mutex> lock(factory_->link->mutex);
    if (factory_->link->parent == &parent_)
    {
        factory_->link->io = nullptr;
        factory_->link->parent = nullptr;
        factory_->link->frame.reset();
        factory_->link->stats.reset();
    }
}

bool ShimTun::tun_send(openvpn::BufferAllocated &buf)
{
    const auto &callbacks = factory_->callbacks;
    if (!up_ || callbacks.tun_send == nullptr)
        return false;
    if (callbacks.tun_send(callbacks.ctx, buf.c_data(), buf.size()) == 0)
        return false;
    if (factory_->stats)
    {
        factory_->stats->inc_stat(openvpn::SessionStats::TUN_BYTES_OUT, buf.size());
        factory_->stats->inc_stat(openvpn::SessionStats::TUN_PACKETS_OUT, 1);
    }
    return true;
}

void ShimTun::apply_push_update(const openvpn::OptionList &opt, openvpn::TransportClient &transcli)
{
    stop();
    openvpn_io::post(io_, [self = openvpn::TunClient::Ptr(this), opt, &transcli]() {
        openvpn::CryptoDCSettings settings{};
        self->tun_start(opt, transcli, settings);
    });
}

class ShimClient final : public openvpn::ClientAPI::OpenVPNClient
{
  public:
    explicit ShimClient(const ovpn_shim_callbacks &callbacks)
        : callbacks_(callbacks), link(std::make_shared<TunLink>())
    {
    }

    std::string cert;
    std::string chain;
    std::shared_ptr<TunLink> link;

    bool pause_on_connection_timeout() override
    {
        return false;
    }

    void event(const openvpn::ClientAPI::Event &event) override
    {
        if (callbacks_.event != nullptr)
            callbacks_.event(callbacks_.ctx, event.error ? 1 : 0, event.fatal ? 1 : 0, view(event.name), view(event.info));
    }

    void acc_event(const openvpn::ClientAPI::AppCustomControlMessageEvent &) override
    {
    }

    void log(const openvpn::ClientAPI::LogInfo &info) override
    {
        if (callbacks_.log != nullptr)
            callbacks_.log(callbacks_.ctx, view(info.text));
    }

    void external_pki_cert_request(openvpn::ClientAPI::ExternalPKICertRequest &request) override
    {
        if (cert.empty())
        {
            request.error = true;
            request.errorText = "This profile has no client certificate";
            return;
        }
        request.cert = cert;
        request.supportingChain = chain;
    }

    void external_pki_sign_request(openvpn::ClientAPI::ExternalPKISignRequest &request) override
    {
        struct Reply
        {
            bool done = false;
            std::string signature;
            std::string error;
        };
        Reply reply;
        if (callbacks_.pki_sign != nullptr)
        {
            callbacks_.pki_sign(callbacks_.ctx,
                                view(request.data),
                                view(request.algorithm),
                                view(request.hashalg),
                                view(request.saltlen),
                                &reply,
                                [](void *reply_ctx, ovpn_shim_str value, ovpn_shim_str error) {
                                    auto *target = static_cast<Reply *>(reply_ctx);
                                    target->done = true;
                                    target->signature = to_string(value);
                                    target->error = to_string(error);
                                });
        }
        if (!reply.done || !reply.error.empty() || reply.signature.empty())
        {
            request.error = true;
            request.errorText = reply.error.empty() ? "The signing callback didn't answer" : reply.error;
            return;
        }
        request.sig = reply.signature;
    }

    openvpn::TunClientFactory *new_tun_factory(const openvpn::ExternalTun::Config &config, const openvpn::OptionList &) override
    {
        return new ShimTunFactory(callbacks_, link, config);
    }

  private:
    ovpn_shim_callbacks callbacks_;
};

void report_status(void *out_ctx, ovpn_shim_status_fn out, bool error, const std::string &status, const std::string &message)
{
    if (out == nullptr)
        return;
    const ovpn_shim_status result{error ? 1 : 0, view(status), view(message)};
    out(out_ctx, &result);
}

void report_status(void *out_ctx, ovpn_shim_status_fn out, const openvpn::ClientAPI::Status &status)
{
    report_status(out_ctx, out, status.error, status.status, status.message);
}

std::string compression_mode(int32_t value)
{
    switch (value)
    {
    case OVPN_SHIM_COMPRESSION_OFF:
        return "no";
    case OVPN_SHIM_COMPRESSION_DOWNLINK:
        return "asym";
    case OVPN_SHIM_COMPRESSION_BOTH:
        return "yes";
    default:
        throw std::invalid_argument("Unknown compression setting");
    }
}

std::string tls_version_min(int32_t value)
{
    switch (value)
    {
    case OVPN_SHIM_TLS_MIN_FROM_PROFILE:
        return "";
    case OVPN_SHIM_TLS_MIN_1_2:
        return "tls_1_2";
    case OVPN_SHIM_TLS_MIN_1_3:
        return "tls_1_3";
    default:
        throw std::invalid_argument("Unknown minimum TLS version");
    }
}

} // namespace

struct ovpn_shim
{
    std::unique_ptr<ShimClient> client;
};

extern "C" {

int32_t ovpn_shim_init_process(void)
{
    // Stops OpenSSL reading an openssl.cnf from a path another user could write to.
    if (OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, nullptr) != 1)
        return 0;
    try
    {
        static auto *helper = new openvpn::ClientAPI::OpenVPNClientHelper();
        (void)helper;
        return 1;
    }
    catch (...)
    {
        return 0;
    }
}

ovpn_shim *ovpn_shim_new(const ovpn_shim_callbacks *callbacks)
{
    if (callbacks == nullptr)
        return nullptr;
    try
    {
        auto *handle = new ovpn_shim();
        handle->client = std::make_unique<ShimClient>(*callbacks);
        return handle;
    }
    catch (...)
    {
        return nullptr;
    }
}

void ovpn_shim_free(ovpn_shim *client)
{
    delete client;
}

int32_t ovpn_shim_eval_config(ovpn_shim *client, const ovpn_shim_config *config, void *out_ctx, ovpn_shim_eval_fn out)
{
    if (client == nullptr || config == nullptr)
        return 0;
    try
    {
        openvpn::ClientAPI::Config settings;
        const WipeOnExit content_guard{settings.content};
        settings.content = to_string(config->profile);
        settings.guiVersion = to_string(config->gui_version);
        settings.compressionMode = compression_mode(config->compression);
        settings.enableNonPreferredDCAlgorithms = config->allow_non_preferred_ciphers != 0;
        settings.tlsVersionMinOverride = tls_version_min(config->tls_version_min);
        settings.autologinSessions = true;
        settings.connTimeout = config->conn_timeout_secs;
        client->client->cert = to_string(config->cert);
        client->client->chain = to_string(config->chain);
        if (!client->client->cert.empty())
            settings.externalPkiAlias = PKI_ALIAS;

        const openvpn::ClientAPI::EvalConfig eval = client->client->eval_config(settings);
        if (out != nullptr)
        {
            const ovpn_shim_eval result{
                eval.error ? 1 : 0,
                view(eval.message),
                eval.autologin ? 1 : 0,
                eval.externalPki ? 1 : 0,
                view(eval.staticChallenge),
                eval.staticChallengeEcho ? 1 : 0,
                view(eval.remoteHost),
                view(eval.remotePort),
                view(eval.remoteProto),
            };
            out(out_ctx, &result);
        }
        return 1;
    }
    catch (const std::exception &error)
    {
        if (out != nullptr)
        {
            const std::string message = error.what();
            const ovpn_shim_eval result{1, view(message), 0, 0, empty_str, 0, empty_str, empty_str, empty_str};
            out(out_ctx, &result);
        }
        return 0;
    }
}

int32_t ovpn_shim_provide_creds(ovpn_shim *client, ovpn_shim_str username, ovpn_shim_str password, ovpn_shim_str response, ovpn_shim_str dynamic_cookie, void *out_ctx, ovpn_shim_status_fn out)
{
    if (client == nullptr)
        return 0;
    try
    {
        openvpn::ClientAPI::ProvideCreds creds;
        const CredsGuard guard{creds};
        creds.username = to_string(username);
        creds.password = to_string(password);
        creds.response = to_string(response);
        creds.dynamicChallengeCookie = to_string(dynamic_cookie);
        report_status(out_ctx, out, client->client->provide_creds(creds));
        return 1;
    }
    catch (const std::exception &error)
    {
        report_status(out_ctx, out, true, "exception", error.what());
        return 0;
    }
}

int32_t ovpn_shim_connect(ovpn_shim *client, void *out_ctx, ovpn_shim_status_fn out)
{
    if (client == nullptr)
        return 0;
    try
    {
        report_status(out_ctx, out, client->client->connect());
        return 1;
    }
    catch (const std::exception &error)
    {
        report_status(out_ctx, out, true, "exception", error.what());
        return 0;
    }
}

void ovpn_shim_stop(ovpn_shim *client)
{
    if (client == nullptr)
        return;
    try
    {
        client->client->stop();
    }
    catch (...)
    {
    }
}

void ovpn_shim_pause(ovpn_shim *client, ovpn_shim_str reason)
{
    if (client == nullptr)
        return;
    try
    {
        client->client->pause(to_string(reason));
    }
    catch (...)
    {
    }
}

void ovpn_shim_resume(ovpn_shim *client)
{
    if (client == nullptr)
        return;
    try
    {
        client->client->resume();
    }
    catch (...)
    {
    }
}

void ovpn_shim_reconnect(ovpn_shim *client, int32_t seconds)
{
    if (client == nullptr)
        return;
    try
    {
        client->client->reconnect(seconds);
    }
    catch (...)
    {
    }
}

void ovpn_shim_transport_stats(ovpn_shim *client, ovpn_shim_stats *out)
{
    if (client == nullptr || out == nullptr)
        return;
    *out = ovpn_shim_stats{0, 0, 0, 0, -1};
    try
    {
        const openvpn::ClientAPI::TransportStats stats = client->client->transport_stats();
        *out = ovpn_shim_stats{stats.bytesIn, stats.bytesOut, stats.packetsIn, stats.packetsOut, stats.lastPacketReceived};
    }
    catch (...)
    {
    }
}

int32_t ovpn_shim_tun_recv(ovpn_shim *client, const uint8_t *data, size_t len)
{
    if (client == nullptr || (data == nullptr && len != 0))
        return 0;
    try
    {
        const std::shared_ptr<TunLink> link = client->client->link;
        std::lock_guard<std::mutex> lock(link->mutex);
        if (link->io == nullptr || link->parent == nullptr || !link->frame)
            return 0;
        const openvpn::Frame::Context &context = (*link->frame)[openvpn::Frame::READ_TUN];
        if (len > context.payload())
            return 0;
        openvpn::BufferAllocated packet;
        context.prepare(packet);
        packet.write(data, len);
        openvpn_io::post(*link->io, [link, packet = std::move(packet)]() mutable {
            openvpn::TunClientParent *parent = nullptr;
            openvpn::SessionStats::Ptr stats;
            {
                std::lock_guard<std::mutex> inner(link->mutex);
                parent = link->parent;
                stats = link->stats;
            }
            if (parent == nullptr)
                return;
            if (stats)
            {
                stats->inc_stat(openvpn::SessionStats::TUN_BYTES_IN, packet.size());
                stats->inc_stat(openvpn::SessionStats::TUN_PACKETS_IN, 1);
            }
            parent->tun_recv(packet);
        });
        return 1;
    }
    catch (...)
    {
        return 0;
    }
}

int32_t ovpn_shim_parse_dynamic_challenge(ovpn_shim_str cookie, void *out_ctx, ovpn_shim_challenge_fn out)
{
    try
    {
        openvpn::ClientAPI::DynamicChallenge challenge;
        if (!openvpn::ClientAPI::OpenVPNClientHelper::parse_dynamic_challenge(to_string(cookie), challenge))
            return 0;
        if (out != nullptr)
        {
            const ovpn_shim_challenge result{view(challenge.challenge), challenge.echo ? 1 : 0, challenge.responseRequired ? 1 : 0, view(challenge.stateID)};
            out(out_ctx, &result);
        }
        return 1;
    }
    catch (...)
    {
        return 0;
    }
}

} // extern "C"
