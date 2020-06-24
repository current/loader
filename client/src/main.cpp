#include "include.h"
#include "util/io.h"
#include "client/client.h"

int main(int argc, char* argv[]) {
  io::init();

  tcp::client client;

  std::thread t{tcp::client::monitor, std::ref(client)};
  t.detach();

  client.start("127.0.0.1", 6666);

  client.receive_event.add([&](tcp::packet_t& packet) {
    if (!packet) return;

    // first packet is the session id and current version
    if (packet.id == 1) {
      client.session_id = packet.session_id;
      tcp::version_t v;
      auto version = fmt::format("{}.{}.{}", v.major, v.minor, v.patch);
      if(version != packet.message) {
        io::logger->error("please update your client");
        client.shutdown();
        return;
      }
    }

    io::logger->info("{}:{}->{}", packet.id, packet.session_id, packet.message);
  });

  while (client) {
    std::string p;
    getline(std::cin, p);

    int ret = client.write(
        tcp::packet_t(p, tcp::packet_type::write, client.session_id));
    if (ret <= 0) {
      break;
    }
  }
}
