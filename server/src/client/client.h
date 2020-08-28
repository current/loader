#pragma once
#include "../server/packet.h"

namespace tcp {

enum client_state { idle = 0, logged_in, waiting, injected };

enum client_response {
  login_fail = 15494,
  hwid_mismatch = 11006,
  login_success = 61539,
  banned = 28618,
  server_error = 98679
};

enum hwid_result {
    blacklisted = 4567,
    version_mismatch = 5472,
    ok = 3247
  };

class client {
  int m_socket;
  SSL* m_ssl;

  std::time_t m_time;

  std::string m_ip;
  std::string m_session_id;

 public:
  uint32_t hwid;
  std::string hwid_data;
  std::string username;
  int state;

  std::time_t security_time;

  client() : m_socket{-1} {};
  client(const int& socket, const std::string_view ip)
      : m_socket{std::move(socket)}, m_ip{ip}, m_ssl{nullptr}, state{-1} {}
  ~client() = default;

  bool init_ssl(SSL_CTX* server_ctx);

  void cleanup() {
    close(m_socket);
    if (m_ssl) {
      SSL_shutdown(m_ssl);
      SSL_free(m_ssl);
    }

    m_socket = -1;
  }

  void reset() {
   std::time(&m_time);
  }

  void reset_security_time() {
    std::time(&security_time);
  }

  bool timeout() { return std::difftime(std::time(nullptr), m_time) >= 300; }

  bool security_timeout() { return std::difftime(std::time(nullptr), security_time) >= 30; }

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

  int stream(const std::string_view str) {
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

  operator bool() const { return m_socket > 0; }
  auto& operator()() { return m_session_id; }
};
};  // namespace tcp