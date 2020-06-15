#include "include.h"
#include "util/io.h"
#include "util/commands.h"
#include "server/server.h"

int main(int argc, char *argv[]) {
  io::init(false);

  tcp::server server("6666");

  server.start();

  server.connect_event.add([&](tcp::client &client) {
    io::logger->info("{} connected.", client.get_ip());
  });

  server.disconnect_event.add([&](tcp::client &client) {
    auto it = std::find_if(server.client_stack.begin(), server.client_stack.end(), [&](tcp::client &c) {
      return client.get_socket() == client.get_socket();
    });

    server.client_stack.erase(it);
    client.cleanup();

    io::logger->info("{} disconnected.", client.get_ip());
  });

  server.receive_event.add([&](tcp::packet_t &packet, tcp::client &client) {
    if (!packet) return;

    io::logger->info("{} : {}", packet.uid.data(), packet.message);

    tcp::packet_t resp("stream", tcp::packet_type::write, "1234567890");
    client.write(resp.message.data(), resp.message.size());

    std::vector<char> out;
    io::read_file("test.dll", out);
    client.stream(out);

  });

  std::thread t{tcp::server::monitor, std::ref(server)};
  t.join();
}
