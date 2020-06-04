#include "include.h"
#include "util/io.h"
#include "client/client.h"

int main(int argc, char *argv[]) {
  tcp::client client;
  if (client.start("127.0.0.1", 6666)) {
    io::logger->info("connected.");
    client.set_state(tcp::client_state::active);
  }

  client.on_recv().add([&](std::string msg) {
    io::logger->info(msg);
  });

  std::thread t{tcp::client::read, std::ref(client)};

  while (client.is_active()) {
    std::string p;
    getline(std::cin, p);

    bool ret = client.send_message(p);
    if (!ret) {
      break;
    }
  }

  t.join();
}
