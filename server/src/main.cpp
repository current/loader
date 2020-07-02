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
    client.write(tcp::packet_t(client_version,
                               tcp::packet_type::write, client.get_session()));

    io::logger->info("{} connected", ip);
  });

  client_server.disconnect_event.add([&](tcp::client& client) {
    auto it = std::find_if(client_server().begin(),
                           client_server().end(), [&](tcp::client& c) {
                             return client.get_socket() == c.get_socket();
                           });

    client_server().erase(it);
    client.cleanup();

    io::logger->info("{} disconnected", client.get_ip());
  });

  client_server.receive_event.add([&](tcp::packet_t& packet, tcp::client& client) {
    auto session = client.get_session();
    auto packet_session = packet.session_id;
    auto ip = client.get_ip();
    auto message = packet();

    if (!packet) {
      io::logger->info("{} sent invalid packet", ip);
      return;
    }

    if (packet_session != session) {
      io::logger->info("{} sent wrong session id", ip);
      return;
    }

    io::logger->info("{} : {}", packet_session, message);

    client.write(tcp::packet_t(message, tcp::packet_type::write,
                       client.get_session()));

    /*auto imports = image.get_json_imports();
    client.stream(imports);*/

    /*std::vector<char> t;
    io::read_file("test.dll", t);
    float tot;
    for(int i = 0; i < 100; i++) {
        float dur;
        client.stream(t, &dur);
        tot += dur;
    }
    float avg = tot / 100.f;
    io::logger->info("average time {}", avg);*/
    
  });

  client_server.timeout_event.add([&](tcp::client& client) {
    client.write(tcp::packet_t("timedout", tcp::packet_type::write,
                               client.get_session()));

    io::logger->info("{} timed out.", client.get_ip());
  });

  std::thread t{tcp::server::monitor, std::ref(client_server)};
  t.join();
}
