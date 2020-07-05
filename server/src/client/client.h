#pragma once
#include "../server/packet.h"

namespace tcp {

class client {
  int m_socket;
  SSL* m_ssl;

  std::time_t m_time;

  std::string m_ip;
  std::string m_session_id;

 public:
  std::string hwid;

  client() : m_socket{-1} {};
  client(const int& socket, const std::string_view ip)
      : m_socket{std::move(socket)}, m_ip{ip}, m_ssl{nullptr} {}
  ~client() = default;

  bool init_ssl(SSL_CTX* server_ctx);

  void cleanup() {
    close(m_socket);
    SSL_shutdown(m_ssl);
    SSL_free(m_ssl);

    m_socket = -1;
  }

  void reset() { std::time(&m_time); }
  bool timeout() { return std::difftime(std::time(nullptr), m_time) >= 300; }

  int write(const packet_t& packet) {
    if (!packet) return 0;
    return write(packet.message.data(), packet.message.size());
  }

  int write(const void* data, size_t size) {
    return SSL_write(m_ssl, data, size);
  }

  int read(void* data, size_t size) { return SSL_read(m_ssl, data, size); }

  int stream(std::vector<char>& data, float* dur = nullptr);
  int read_stream(std::vector<char>& out);

  int stream(std::string& str) {
    std::vector<char> vec(str.begin(), str.end());
    return stream(vec);
  }

  int read_stream(std::string& str) {
    std::vector<char> out;
    int ret = read_stream(out);
    str.assign(out.begin(), out.end());
    return ret;
  }

  void gen_session();

  int& get_socket() { return m_socket; }
  auto& get_ip() { return m_ip; }
  auto& get_session() { return m_session_id; }

  operator bool() const { return m_ssl && m_socket > 0; }
};
};  // namespace tcp