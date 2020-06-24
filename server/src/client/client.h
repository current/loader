#pragma once
#include "../server/packet.h"

namespace tcp {

class client {
  int m_socket;
  SSL* m_ssl;

  time_t m_time;

  std::string m_ip;
  std::string m_session_id;

 public:
  client() : m_socket{-1} {};
  client(const int& socket, const std::string_view ip)
      : m_socket{std::move(socket)}, m_ip{ip}, m_ssl{nullptr} {}
  ~client() = default;

  bool init_ssl(SSL_CTX* server_ctx);

  void cleanup() {
    close(m_socket);
    SSL_shutdown(m_ssl);
    SSL_free(m_ssl);
  }

  int write(void* data, size_t size) { return SSL_write(m_ssl, data, size); }

  int write(const packet_t& packet) {
    if (!packet) return 0;
    return SSL_write(m_ssl, packet.message.data(), packet.message.size());
  }

  int read(void* data, size_t size) { return SSL_read(m_ssl, data, size); }

  int stream(std::vector<char>& data);
  int read_stream(std::vector<char>& out);

  void gen_session();

  int get_socket() { return m_socket; }
  auto get_ip() { return m_ip; }
  auto get_session() { return m_session_id; }
};
};  // namespace tcp