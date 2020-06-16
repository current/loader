#pragma once
#include "../util/io.h"
#include "../util/events.h"
#include "packet.h"

namespace tcp {

enum client_state : uint8_t { idle = 0, active, standby };

class client {
  int m_socket;
  std::atomic<uint8_t> m_state;

  SSL *m_server_ssl;
  SSL_CTX *m_ssl_ctx;

  std::string m_session_id;
 public:
  event<packet_t &> receive_event;

  client() : m_socket{-1}, m_state{0} {}

  bool start(const std::string_view server_ip, const uint16_t port);

  int write(void *data, size_t size) {
    return SSL_write(m_server_ssl, data, size);
  }

  int read(void *data, size_t size) {
    return SSL_read(m_server_ssl, data, size);
  }

  int read_stream(std::vector<char> &out);
  int stream(std::vector<char> &data);

  bool set_session();

  int get_socket() { return m_socket; }
  bool is_active() { return m_state == client_state::active; }
  void set_state(const uint8_t &state) { m_state = state; }

  static void monitor(client &client) {
    std::array<char, 4096> buf;
    while (client.is_active()) {
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
