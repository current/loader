#include "include.h"
#include "util/io.h"
#include "client/client.h"

int main(int argc, char *argv[]) {
  io::init();
  
  tcp::client client;

  if (client.start("127.0.0.1", 6666)) {
    io::logger->info("connected.");
    client.set_state(tcp::client_state::active);
  }

  client.receive_event.add([&](tcp::packet_t &packet) {
    if(!packet)
      return;

    io::logger->info(packet.message);
    io::logger->info(packet.uid.data());
  });

  std::thread t{tcp::client::monitor, std::ref(client)};

  while (client.is_active()) {
    std::string p;
    getline(std::cin, p);

    tcp::packet_t packet(p, tcp::packet_type::write, "1234567890");

    bool ret = client.write(packet.message.data(), packet.message.size());
    if (!ret) {
      break;
    }
  }

  t.join();
}
