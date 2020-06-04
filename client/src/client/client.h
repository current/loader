#pragma once
#include "../util/io.h"
#include "../util/events.h"

namespace tcp {

enum client_state : uint8_t {
	idle = 0,
	active,
	standby
};

class client {
  int m_socket;
  std::atomic<uint8_t> m_state;

  event<std::string> receive_event;

 public:
  client() : m_socket{-1}, m_state{0} {}
  bool start(const std::string_view server_ip, const uint16_t &port);

  bool send_message(const std::string_view msg) {
    int ret = send(m_socket, msg.data(), msg.size(), 0);
    return ret == msg.size();
  }

  int get_socket() { return m_socket; }
  bool is_active() { return m_state == client_state::active; }
  void set_state(const uint8_t &state) { m_state = state; }
  auto &on_recv() { return receive_event; }

  static void read(client &client) {
    std::array<char, 256> buf;
    while (client.is_active()) {
      int ret = recv(client.get_socket(), &buf[0], buf.size(), 0);
      if (ret <= 0) {
        io::logger->error("connection lost.");
        break;
      }

      std::string msg(buf.data(), ret);
      client.on_recv().call(msg);
    }
  }
};
}  // namespace tcp
