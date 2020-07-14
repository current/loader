#include "include.h"
#include "util/io.h"
#include "util/commands.h"
#include "server/server.h"
#include "image/pe.h"

constexpr std::string_view version{"0.1.0"};

int main(int argc, char* argv[]) {
  io::init(false);

  tcp::server client_server("6666");

  client_server.start();

  client_server.connect_event.add([&](tcp::client& client) {
    auto ip = client.get_ip();

    io::logger->info("{} connected.", ip);

    client.gen_session();
    client.write(tcp::packet_t(version, tcp::packet_type::write, client(),
                               tcp::packet_id::session));

    client.state = tcp::client_state::idle;
  });

  client_server.disconnect_event.add([&](tcp::client& client) {
    client.cleanup();

    auto it = std::find_if(
        client_server().begin(), client_server().end(),
        [&](tcp::client& c) { return c.get_socket() == client.get_socket(); });

    if (it != client_server().end()) {
      client_server().erase(it);
    }

    io::logger->info("{} disconnected.", client.get_ip());
  });

  client_server.receive_event.add([&](tcp::packet_t& packet,
                                      tcp::client& client) {
    auto session = client();
    auto packet_session = packet.session_id;
    auto ip = client.get_ip();
    auto message = packet();
    auto id = packet.id;

    if (!packet) {
      io::logger->warn("{} sent invalid packet.", ip);

      client_server.disconnect_event.call(client);
      return;
    }

    if (packet_session != session) {
      io::logger->warn("{} sent wrong session id.", ip);

      client_server.disconnect_event.call(client);
      return;
    }

    io::logger->info("{} : {}", packet_session, message);

    if (id == tcp::packet_id::hwid) {
      client.hwid = message;

      io::logger->info("got hwid from {} : {}", ip, message);

      if (client_server.bl().find(message)) {
        io::logger->warn("{} is hwid banned.", ip);

        client.write(tcp::packet_t(message, tcp::packet_type::write, session,
                                   tcp::packet_id::ban));

        client_server.disconnect_event.call(client);
        return;
      }
    }

    if (id == tcp::packet_id::login_req) {
      if (client.state != tcp::client_state::idle) {
        return;
      }

      auto pos = message.find(",");
      if (pos != std::string::npos) {
        auto user = message.substr(0, pos);
        auto pass = message.substr(pos + 1);

        user_data data{};
        nlohmann::json json;

        io::logger->info("{} is trying to login from {}.", user, ip);

        // int ret = forum_response::api_error;
        int ret = client_server.forum().check_login(user, pass, data);
        if (ret == forum_response::api_success) {
          if (data.banned) {
            io::logger->warn("{} is forum banned, dropping...", user);

            json["result"] = tcp::client_response::banned;

            client.write(tcp::packet_t(json.dump(), tcp::packet_type::write,
                                       session, tcp::packet_id::login_resp));

            client_server.disconnect_event.call(client);
            return;
          }

          // new user/no hwid, register the hwid on the forums
          if (data.hwid.empty()) {
            io::logger->info("{} is new, registering hwid...", user);
            if (!client_server.forum().edit(data.id, "custom_fields[hwid]",
                                            client.hwid)) {
              io::logger->warn("failed to register hwid for {}.", user);
            }

            data.hwid = client.hwid;
          }

          // invalid hwid
          if (data.hwid != client.hwid) {
            io::logger->warn("{}'s hwid doesn't match.");
            if (!client_server.forum().edit(data.id, "custom_fields[new_hwid]",
                                            client.hwid)) {
              io::logger->warn("failed to write new hwid for {}.", user);
            }

            json["result"] = tcp::client_response::hwid_mismatch;

            client.write(tcp::packet_t(json.dump(), tcp::packet_type::write,
                                       session, tcp::packet_id::login_resp));

            client_server.disconnect_event.call(client);
            return;
          }

          json["result"] = tcp::client_response::login_success;

          client.write(tcp::packet_t(json.dump(), tcp::packet_type::write,
                                     session, tcp::packet_id::login_resp));

          client.state = tcp::client_state::logged_in;

          io::logger->info("{} logged in successfuly.", user);
        }

        if (ret == forum_response::api_timeout ||
            ret == forum_response::api_fail) {
          json["result"] = tcp::client_response::server_error;

          io::logger->info("internal server error on {}'s login request.", user);

          client.write(tcp::packet_t(json.dump(), tcp::packet_type::write,
                                     session, tcp::packet_id::login_resp));
        }

        if (ret == forum_response::api_error) {
          json["result"] = tcp::client_response::login_fail;

          io::logger->info("{} failed to login.", user);

          client.write(tcp::packet_t(json.dump(), tcp::packet_type::write,
                                     session, tcp::packet_id::login_resp));
        }
      }
    }

    client.write(tcp::packet_t(message, tcp::packet_type::write, session));
  });

  client_server.timeout_event.add([&](tcp::client& client) {
    client.cleanup();

    auto it = std::find_if(
        client_server().begin(), client_server().end(),
        [&](tcp::client& c) { return c.get_socket() == client.get_socket(); });

    if (it != client_server().end()) {
      client_server().erase(it);
    }

    io::logger->info("{} timed out.", client.get_ip());
  });

  std::thread t{tcp::server::monitor, std::ref(client_server)};
  t.join();
}
