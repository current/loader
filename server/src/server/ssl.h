#pragma once

class ssl {
  std::string_view m_cert, m_key, m_ca;
  std::string m_passphrase;
  SSL_CTX* m_ctx;

 public:
  ssl(const std::string_view cert, const std::string_view key,
      const std::string_view ca = "")
      : m_cert{cert}, m_key{key}, m_ca{ca}, m_ctx{nullptr} {
    SSL_library_init();
  }
  ~ssl() = default;

  bool init() {
    m_ctx = SSL_CTX_new(TLS_server_method());
    if (!m_ctx) {
      io::logger->error("failed to create ssl context.");
      return false;
    }

    SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER, 0);
    int res = SSL_CTX_use_certificate_chain_file(m_ctx, m_cert.data());
    if (res != 1) {
      io::logger->error("failed to load certificate.");
      return false;
    }

    if (!m_passphrase.empty())
      SSL_CTX_set_default_passwd_cb_userdata(m_ctx, m_passphrase.data());

    res = SSL_CTX_use_PrivateKey_file(m_ctx, m_key.data(), SSL_FILETYPE_PEM);
    if (res != 1) {
      io::logger->error("failed to load private key.");
      return false;
    }

    res = SSL_CTX_check_private_key(m_ctx);
    if (res != 1) {
      io::logger->error("failed to verify private key.");
      return false;
    }

    res = SSL_CTX_load_verify_locations(m_ctx, m_ca.data(), nullptr);
    if (res != 1) {
      io::logger->error("failed to load root ca.");
      return false;
    }


    return true;
  }

  void set_passphrase(const std::string_view phrase) { m_passphrase = phrase; }
  auto& get_context() { return m_ctx; }
};
