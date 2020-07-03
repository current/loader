#include "include.h"
#include "util/io.h"
#include "client/client.h"
#include "assembler/assembler.h"

int main(int argc, char* argv[]) {
  io::init();

  assembler::assembler a;
  a.push({1, 2, 3, 7, 9});
  a.end();
  for(auto &b : a()) {
    io::logger->info("{:x}", b);
  }

  
  std::cin.get();
  tcp::client client;

  std::thread t{tcp::client::monitor, std::ref(client)};
  t.detach();

  client.start("127.0.0.1", 6666);

  client.receive_event.add([&](tcp::packet_t& packet) {
    if (!packet) return;
    auto message = packet();

    // first packet is the session id and current version
    if (packet.id == 1) {
      client.session_id = packet.session_id;
      tcp::version_t v{0, 1, 0};
      auto version = fmt::format("{}.{}.{}", v.major, v.minor, v.patch);
      if(version != message) {
        io::logger->error("please update your client");
        client.shutdown();
      }
      return;
    }

    if (message == "timedout") {
      io::logger->warn("connection timeout.");
      client.shutdown();
    }

    io::logger->info("{}:{}->{}", packet.id, packet.session_id, message);

    std::string imports;
    client.read_stream(imports);

    auto json = nlohmann::json::parse(imports);
    std::ofstream o("o");
    o << std::setw(4) << json;
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
