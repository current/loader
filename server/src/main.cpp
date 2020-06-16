#include "include.h"
#include "util/io.h"
#include "util/commands.h"
#include "server/server.h"

int main(int argc, char *argv[]) {
  io::init(false);

  tcp::server server("6666");

  server.start();

  server.connect_event.add([&](tcp::client &client) {
    auto ip = client.get_ip();

    io::logger->info("{} connected", ip);

    // generate unique client session
    client.gen_session();

    auto session = client.get_session();

    io::logger->info("generated session id {} for {}", session,
                     ip);

    // send the assigned session id to client
    tcp::packet_t packet(session, tcp::packet_type::write);
    client.write(packet);
  });

  server.disconnect_event.add([&](tcp::client &client) {
    auto it = std::find_if(server.client_stack.begin(),
                           server.client_stack.end(), [&](tcp::client &c) {
                             return client.get_socket() == client.get_socket();
                           });

    server.client_stack.erase(it);
    client.cleanup();

    io::logger->info("{} disconnected", client.get_ip());
  });

  server.receive_event.add([&](tcp::packet_t &packet, tcp::client &client) {
    auto session = client.get_session();
    auto packet_session = packet.session_id;
    auto ip = client.get_ip();
    auto message = packet.message;

    if (!packet) {
      io::logger->info("{} sent invalid packet", ip);
      return;
    }

    if(packet_session != session) {
      io::logger->info("{} sent wrong session id", ip);
      return;
    }

    io::logger->info("{} : {}", packet_session, packet.message);

    tcp::packet_t resp("stream", tcp::packet_type::write, client.get_session());
    client.write(resp);

    std::vector<char> out;
    io::read_file("test.dll", out);
    client.stream(out);
  });

  std::thread t{tcp::server::monitor, std::ref(server)};
  t.join();
}
