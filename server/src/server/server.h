#pragma once
#include "../client/client.h"
#include "../util/events.h"
#include "ssl.h"

namespace tcp {
constexpr uint8_t server_version = 0;

enum select_status : int { error = 0, standby, ready };

class server {
  int m_socket;
  std::string_view m_port;

  fd_set m_server_set;
  SSL_CTX* m_ctx;

  std::atomic<bool> m_active;

  std::vector<tcp::client> client_stack;
 public:
  event<client&> connect_event;
  event<packet_t&, client&> receive_event;
  event<client&> disconnect_event;
  event<client&> timeout_event;

  server(const std::string_view port) : m_port{port}, m_active{false} {}
  ~server() = default;

  void start();
  select_status peek();
  void accept_client();
  void receive();
  void stop();
  void check_timeout();

  operator bool() const { return m_active; }
  auto &operator()() { return client_stack; }

  static void monitor(server& srv) {
    while (srv) {
      auto ret = srv.peek();
      if (ret == select_status::ready) {
        srv.accept_client();
        srv.receive();
      } else if (ret == select_status::standby) {
        srv.check_timeout();
      } else {
        break;
      }
    }
  }
};

};  // namespace tcp
