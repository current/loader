#pragma once
#include "../server/packet.h"

namespace tcp {
constexpr uint8_t client_version = 0;

class client {
  int m_socket;
  SSL *m_ssl;

  time_t m_time;

  std::string m_ip;
  std::array<char, tcp::uid_len> m_uid;
 public:
  client() : m_socket{-1} {};
  client(const int &socket, const std::string_view ip)
      : m_socket{std::move(socket)}, m_ip{ip}, m_ssl{nullptr} {
    
  }
  ~client() = default;

  bool init_ssl(SSL_CTX *server_ctx);

  void cleanup() {
    close(m_socket);
    SSL_shutdown(m_ssl);
    SSL_free(m_ssl);
  }

  int write(void *data, size_t size) {
    return SSL_write(m_ssl, data, size);
  }

  int read(void *data, size_t size) {
    return SSL_read(m_ssl, data, size);
  }

  bool set_uid(const std::string_view uid_str) {
    const size_t uid_str_len = uid_str.size();
    if (uid_str_len != tcp::uid_len) {
      io::logger->error("packet uid len mismatch!");
      return false;
    }

    for (size_t i = 0; i < uid_len; ++i) {
      m_uid[i] = uid_str[i];
    }

    return true;
  }

  int &get_socket() { return m_socket; }
  auto &get_ip() { return m_ip; }
  auto &get_uid() { return m_uid; }
};
};  // namespace tcp