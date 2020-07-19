#pragma once

#include <wolfssl/ssl.h>

#include "../util/io.h"
#include "../util/events.h"
#include "../injection/mapper.h"
#include "packet.h"

namespace tcp {

struct version_t {
  uint8_t major;
  uint8_t minor;
  uint8_t patch;
};

enum client_state {
  idle = 0, logged_in, waiting
};

enum login_result {
  login_fail = 15494,
  hwid_mismatch = 11006,
  login_success = 61539,
  banned = 28618,
  server_error = 98679
};

class client {
  int m_socket;
  std::atomic<bool> m_active;

  WOLFSSL* m_server_ssl;
  WOLFSSL_CTX* m_ssl_ctx;

 public:
  int state;
  mmap::data mapper_data;

  std::string session_id;
  event<packet_t&> receive_event;
  event<> connect_event;

  client() : m_socket{-1}, m_active{false}, state{client_state::idle} {}

  void start(const std::string_view server_ip, const uint16_t port);

  int write(const packet_t& packet) {
    if (!packet) return 0;
    return write(packet.message.data(),
                     packet.message.size());
  }

  int write(const void* data, size_t size) {
    return wolfSSL_write(m_server_ssl, data, size);
  }

  int read(void* data, size_t size) {
    return wolfSSL_read(m_server_ssl, data, size);
  }

  int read_stream(std::vector<char>& out);
  int stream(std::vector<char>& data);

  int stream(std::string &str) {
    std::vector<char> vec(str.begin(), str.end());
    return stream(vec);
  }

  int read_stream(std::string &str) {
    std::vector<char> out;
    int ret = read_stream(out);
    str.assign(out.begin(), out.end());
    return ret;
  }

  int get_socket() { return m_socket; }

  operator bool() const { return m_active; }

  void shutdown() {
    closesocket(m_socket);
    wolfSSL_shutdown(m_server_ssl);
    wolfSSL_free(m_server_ssl);

    m_active = false;
  }

  static void monitor(client& client) {
    while (!client) std::this_thread::sleep_for(std::chrono::milliseconds(100));

    std::array<char, message_len> buf;
    while (client) {
      int ret = client.read(&buf[0], buf.size());
      if (ret <= 0) {
        io::logger->error("connection lost.");
        break;
      }
      std::string msg(buf.data(), ret);
      packet_t packet(msg, packet_type::read);

      client.receive_event.call(packet);
    }
  }
};
}  // namespace tcp

