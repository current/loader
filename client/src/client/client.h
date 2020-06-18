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

 public:
  static constexpr int version = 0;
  std::string session_id;
  event<packet_t &> receive_event;

  client() : m_socket{-1}, m_state{0} {}

  bool start(const std::string_view server_ip, const uint16_t port);

  int write(const packet_t &packet) {
    if (!packet) return 0;
    return SSL_write(m_server_ssl, packet.message.data(),
                     packet.message.size());
  }

  int write(void *data, size_t size) {
    return SSL_write(m_server_ssl, data, size);
  }

  int read(void *data, size_t size) {
    return SSL_read(m_server_ssl, data, size);
  }

  int read_stream(std::vector<char> &out);
  int stream(std::vector<char> &data);

  int get_socket() { return m_socket; }
  void set_state(const uint8_t state) { m_state = state; }

  operator bool() const { return m_state == client_state::active; }

  static void monitor(client &client) {
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
