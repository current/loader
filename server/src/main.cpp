#include "include.h"
#include "util/io.h"
#include "util/commands.h"
#include "server/server.h"
#include "image/pe.h"

constexpr std::string_view client_version{"0.1.0"};

int main(int argc, char* argv[]) {
  io::init(false);

  pe::image test("out");

  for(auto&[mod, imports] : test.imports()) {
    io::logger->info(mod);
    for(auto &i : imports) {
      io::logger->info("  {}->{:x}", i.name, i.rva);
    }
  }

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
    auto it = std::find_if(client_server.client_stack.begin(),
                           client_server.client_stack.end(), [&](tcp::client& c) {
                             return client.get_socket() == client.get_socket();
                           });

    client_server.client_stack.erase(it);
    client.cleanup();

    io::logger->info("{} disconnected", client.get_ip());
  });

  client_server.receive_event.add([&](tcp::packet_t& packet, tcp::client& client) {
    auto session = client.get_session();
    auto packet_session = packet.session_id;
    auto ip = client.get_ip();
    auto message = packet.message;

    if (!packet) {
      io::logger->info("{} sent invalid packet", ip);
      return;
    }

    if (packet_session != session) {
      io::logger->info("{} sent wrong session id", ip);
      return;
    }

    io::logger->info("{} : {}", packet_session, packet.message);

    tcp::packet_t resp(packet.message, tcp::packet_type::write,
                       client.get_session());
    client.write(resp);

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

  std::thread t{tcp::server::monitor, std::ref(client_server)};
  t.join();
}
