#include "include.h"
#include "util/io.h"
#include "util/commands.h"
#include "server/server.h"
#include "image/pe.h"

constexpr std::string_view version{"0.1.0"};

int main(int argc, char* argv[]) {
  io::init(false);

  tcp::server client_server("6666");

  client_server.start();

  client_server.connect_event.add([&](tcp::client& client) {
    auto ip = client.get_ip();

    io::logger->info("{} connected.", ip);

    client.gen_session();
    client.write(tcp::packet_t(version, tcp::packet_type::write, client(),
                               tcp::packet_id::session));
  });

  client_server.disconnect_event.add([&](tcp::client& client) {
    client.cleanup();

    auto it = std::find_if(
        client_server().begin(), client_server().end(),
        [&](tcp::client& c) { return c.get_socket() == client.get_socket(); });

    if (it != client_server().end()) {
      client_server().erase(it);
    }

    io::logger->info("{} disconnected.", client.get_ip());
  });

  client_server.receive_event.add([&](tcp::packet_t& packet,
                                      tcp::client& client) {
    auto session = client();
    auto packet_session = packet.session_id;
    auto ip = client.get_ip();
    auto message = packet();
    auto id = packet.id;

    if (!packet) {
      io::logger->warn("{} sent invalid packet.", ip);

      // client_server.disconnect_event.call(client);
      return;
    }

    if (packet_session != session) {
      io::logger->warn("{} sent wrong session id.", ip);

      // client_server.disconnect_event.call(client);
      return;
    }

    io::logger->info("{} : {}", packet_session, message);

    if (id == tcp::packet_id::hwid) {
      client.hwid = message;

      // client_server.bl().add({ip, message});

      io::logger->info("got hwid from {} : {}", ip, message);

      if (client_server.bl().find(message)) {
        io::logger->warn("{} is hwid banned.", ip);

        client_server.disconnect_event.call(client);
        return;
      }
    }

    client.write(tcp::packet_t(message, tcp::packet_type::write, session));
  });

  client_server.timeout_event.add([&](tcp::client& client) {
    client.cleanup();

    auto it = std::find_if(
        client_server().begin(), client_server().end(),
        [&](tcp::client& c) { return c.get_socket() == client.get_socket(); });

    if (it != client_server().end()) {
      client_server().erase(it);
    }

    io::logger->info("{} timed out.", client.get_ip());
  });

  std::thread t{tcp::server::monitor, std::ref(client_server)};
  t.join();
}
