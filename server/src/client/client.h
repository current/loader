#pragma once
#include "../server/packet.h"

namespace tcp {
constexpr uint8_t client_version = 0;

class client {
  int m_socket;
  SSL *m_ssl;

  time_t m_time;

  std::string m_ip;
  std::string m_uid;

 public:
  client() : m_socket{-1} {};
  client(const int &socket, const std::string_view ip)
      : m_socket{std::move(socket)}, m_ip{ip}, m_ssl{nullptr} {}
  ~client() = default;

  bool init_ssl(SSL_CTX *server_ctx);

  void cleanup() {
    close(m_socket);
    SSL_shutdown(m_ssl);
    SSL_free(m_ssl);
  }

  int write(void *data, size_t size) { return SSL_write(m_ssl, data, size); }

  int read(void *data, size_t size) { return SSL_read(m_ssl, data, size); }

  int stream(std::vector<char> &data);

  int read_stream(std::vector<char> &out);

  void set_uid(const std::string_view uid_str) { m_uid = uid_str; }

  int &get_socket() { return m_socket; }
  auto &get_ip() { return m_ip; }
  auto &get_uid() { return m_uid; }
};
};  // namespace tcp