#include "include.h"
#include "util/io.h"
#include "client/client.h"
#include "assembler/assembler.h"

int main(int argc, char* argv[]) {
  io::init();

  /*assembler a;
  a.push({1, 2, 3, 7, 9});
  a.end();
  for(auto &b : a()) {
    io::logger->info("{:x}", b);
  }
  std::cin.get();*/

  tcp::client client;

  std::thread t{tcp::client::monitor, std::ref(client)};
  t.detach();

  client.start("127.0.0.1", 6666);

  client.connect_event.add([&]() { io::logger->info("connected."); });

  client.receive_event.add([&](tcp::packet_t& packet) {
    if (!packet) return;
    auto message = packet();
    auto id = packet.id;

    if (id == tcp::packet_id::session) {
      client.session_id = packet.session_id;

      tcp::version_t v{0, 1, 0};
      auto version = fmt::format("{}.{}.{}", v.major, v.minor, v.patch);
      io::logger->info("current server version {}", message);

      if (version != message) {
        io::logger->error("please update your client.");
        client.shutdown();
      }

      int ret =
          client.write(tcp::packet_t("hwid", tcp::packet_type::write,
                                     client.session_id, tcp::packet_id::hwid));
      if (ret <= 0) {
        io::logger->error("failed to send hwid.");
        client.shutdown();
      }
    }

    if (id == tcp::packet_id::login_resp) {
      auto j = nlohmann::json::parse(message);

      auto res = j["result"].get<int>();
      if (res == tcp::login_result::banned) {
        io::logger->error("your account is banned.");
        client.shutdown();
      }

      io::logger->info("res {}", res);
    }

    io::logger->info("{}:{}->{} {}", packet.seq, packet.session_id, message,
                     id);
  });

  while (client) {
    std::string u;
    getline(std::cin, u);

    std::string p;
    getline(std::cin, p);

    auto l = fmt::format("{},{}", u, p);

    int ret = client.write(tcp::packet_t(l, tcp::packet_type::write,
                                         client.session_id,
                                         tcp::packet_id::login_req));

    if (ret <= 0) {
      return 0;
    }
  }
}
