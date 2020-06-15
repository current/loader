#include "include.h"
#include "util/io.h"
#include "client/client.h"

int main(int argc, char *argv[]) {
  io::init();
  
  tcp::client client;

  if (client.start("127.0.0.1", 6666)) {
    if(!client.set_uid()) {
      io::logger->error("failed to set session id.");
      return 0;
    }

    io::logger->info("connected.");
    client.set_state(tcp::client_state::active);
  }

  client.receive_event.add([&](tcp::packet_t &packet) {
    if(!packet)
      return;

    io::logger->info(packet.message);
    if(packet.message == "stream") {
      std::vector<char> dat;
      client.read_stream(dat);

      std::ofstream o("out");
      o.write(dat.data(), dat.size());
      o.close();
    }
  });

  std::thread t{tcp::client::monitor, std::ref(client)};

  while (client.is_active()) {
    std::string p;
    getline(std::cin, p);

    tcp::packet_t packet(p, tcp::packet_type::write, "1234567890");

    int ret = client.write(packet.message.data(), packet.message.size());
    if (ret <= 0) {
      break;
    }

  }

  t.join();
}
