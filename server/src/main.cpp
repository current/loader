#include "include.h"
#include "util/io.h"
#include "util/commands.h"
#include "server/server.h"
#include "image/pe.h"

constexpr std::string_view client_version{"0.1.0"};

int main(int argc, char* argv[]) {
  io::init(false);

  //pe::image image("test.dll");

  tcp::server client_server("6666");

  client_server.start();

  client_server.connect_event.add([&](tcp::client& client) {
    auto ip = client.get_ip();
    client.gen_session();
    client.write(tcp::packet_t(client_version, tcp::packet_type::write,
                               client.get_session(),
                               tcp::packet_action::session));

    io::logger->info("{} connected", ip);
  });

  client_server.disconnect_event.add([&](tcp::client& client) {
    client.cleanup();

    io::logger->info("{} disconnected", client.get_ip());
  });

  client_server.receive_event.add([&](tcp::packet_t& packet, tcp::client& client) {
    auto session = client.get_session();
    auto packet_session = packet.session_id;
    auto ip = client.get_ip();
    auto message = packet();
    auto action = packet.act;

    if (!packet) {
      io::logger->info("{} sent invalid packet", ip);
      return;
    }

    if (packet_session != session) {
      io::logger->info("{} sent wrong session id", ip);
      return;
    }

    io::logger->info("{} : {}", packet_session, message);

    if(action == tcp::packet_action::hwid) {
      client.hwid = message;

      io::logger->info("got hwid from {} : {}", ip, message);
    }

    //client.write(tcp::packet_t(message, tcp::packet_type::write,
                       //client.get_session()));
  });

  client_server.timeout_event.add([&](tcp::client& client) {
    client.cleanup();
    io::logger->info("{} timed out.", client.get_ip());
  });

  std::thread t{tcp::server::monitor, std::ref(client_server)};
  t.join();
}
