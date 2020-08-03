#include "include.h"
#include "util/io.h"
#include "util/commands.h"
#include "server/server.h"

constexpr std::string_view version{"0.1.1"};

int main(int argc, char* argv[]) {
  io::init(true);

  tcp::server client_server("6666");

  // id 0 : notepad test dll
  client_server.images["notepad++.exe"] = pe::image<false>("img.dll");

  // x64 image test
  client_server.images64["sublime_text.exe"] = pe::image<true>("img64.dll");

  client_server.start();

  uint16_t ver;
  for (int i = 0; i < version.size(); ++i) {
    if (i % 2) {
      continue;
    }

    ver += static_cast<uint8_t>(version[i]) << 5;
  }
  io::logger->info("client version {}.", ver);

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
      if (!nlohmann::json::accept(message)) {
        io::logger->warn("{} sent invalid hwid packet.", ip);

        client_server.disconnect_event.call(client);
        return;
      }
      auto j = nlohmann::json::parse(message);
      if (j.contains("uid")) client.hwid = j["uid"];

      client.hwid_data = message;

      io::logger->info("got hwid from {} : {}", ip, client.hwid);

      client.reset_security_time();

      if (client_server.bl().find(client.hwid)) {
        io::logger->warn("{} is hwid banned.", ip);

        client.write(tcp::packet_t(message, tcp::packet_type::write, session,
                                   tcp::packet_id::ban));

        client_server.disconnect_event.call(client);
        return;
      }
    }

    if (id == tcp::packet_id::security_report) {
      client.reset_security_time();
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

        int ret = forum_response::api_success;
        // int ret = client_server.forum().check_login(user, pass, data);
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
                                            std::to_string(client.hwid))) {
              io::logger->warn("failed to register hwid for {}.", user);
            }

            if (!client_server.forum().edit(data.id, "custom_fields[hwid_data]",
                                            client.hwid_data)) {
              io::logger->warn("failed to register hwid data for {}.", user);
            }

            data.hwid = std::to_string(client.hwid);
          }

          // invalid hwid
          if (data.hwid != std::to_string(client.hwid)) {
            io::logger->warn("{}'s hwid doesn't match.", user);
            if (!client_server.forum().edit(data.id, "custom_fields[new_hwid]",
                                            std::to_string(client.hwid))) {
              io::logger->warn("failed to write new hwid for {}.", user);
            }

            if (!client_server.forum().edit(data.id,
                                            "custom_fields[new_hwid_data]",
                                            client.hwid_data)) {
              io::logger->warn("failed to write new hwid data for {}.", user);
            }

            json["result"] = tcp::client_response::hwid_mismatch;

            client.write(tcp::packet_t(json.dump(), tcp::packet_type::write,
                                       session, tcp::packet_id::login_resp));

            client_server.disconnect_event.call(client);
            return;
          }

          json["result"] = tcp::client_response::login_success;
          json["games"]["notepad"] = {{"version", 1},
                                      {"id", 0},
                                      {"process", "notepad++.exe"},
                                      {"x64", false}};
          json["games"]["sublime text"] = {{"version", 1},
                                           {"id", 1},
                                           {"process", "sublime_text.exe"},
                                           {"x64", true}};

          client.write(tcp::packet_t(json.dump(), tcp::packet_type::write,
                                     session, tcp::packet_id::login_resp));

          client.username = user;
          client.state = tcp::client_state::logged_in;

          io::logger->info("{} logged in successfuly.", user);
        }

        if (ret == forum_response::api_timeout ||
            ret == forum_response::api_fail) {
          json["result"] = tcp::client_response::server_error;

          io::logger->info("internal server error on {}'s login request.",
                           user);

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

    if (id == tcp::packet_id::game_select) {
      if (client.state != tcp::client_state::logged_in) {
        return;
      }

      if (!nlohmann::json::accept(message)) {
        io::logger->warn("{} sent invalid game select packet.", ip);

        client_server.disconnect_event.call(client);
        return;
      }

      auto resp = nlohmann::json::parse(message);
      if (!resp.contains("id") || !resp.contains("x64")) {
        io::logger->warn("invalid game select json response for {}.", ip);

        client_server.disconnect_event.call(client);
        return;
      }
      std::string id = resp["id"];
      bool x64 = resp["x64"];

      if (x64) {
        auto it = client_server.images64.find(id);
        if (it == client_server.images64.end()) {
          io::logger->warn("{} sent invalid game id.");

          client_server.disconnect_event.call(client);
          return;
        }
        auto& img = it->second;

        io::logger->info("{} selected game id {}.", client.username, id);
        auto nt = img->get_nt_headers();

        nlohmann::json j;
        j["pe"].emplace_back(nt->optional_header.size_image);
        j["pe"].emplace_back(nt->optional_header.entry_point);

        auto imports = img.get_json_imports();

        j["size"] = imports.size();

        client.write(tcp::packet_t(j.dump(), tcp::packet_type::write, session,
                                   tcp::packet_id::game_select));

        if (client.stream(imports) == imports.size()) {
          io::logger->info("sent imports to {}.", client.username);
        }

        client.state = tcp::client_state::waiting;
      } else {
        auto it = client_server.images.find(id);
        if (it == client_server.images.end()) {
          io::logger->warn("{} sent invalid game id.");

          client_server.disconnect_event.call(client);
          return;
        }
        auto& img = it->second;

        io::logger->info("{} selected game id {}.", client.username, id);
        auto nt = img->get_nt_headers();

        nlohmann::json j;
        j["pe"].emplace_back(nt->optional_header.size_image);
        j["pe"].emplace_back(nt->optional_header.entry_point);

        auto imports = img.get_json_imports();

        j["size"] = imports.size();

        client.write(tcp::packet_t(j.dump(), tcp::packet_type::write, session,
                                   tcp::packet_id::game_select));

        if (client.stream(imports) == imports.size()) {
          io::logger->info("sent imports to {}.", client.username);
        }

        client.state = tcp::client_state::waiting;
      }
    }

    if (id == tcp::packet_id::image) {
      if (client.state != tcp::client_state::waiting) {
        return;
      }

      if (!nlohmann::json::accept(message)) {
        io::logger->warn("{} sent invalid image packet.", ip);

        client_server.disconnect_event.call(client);
        return;
      }

      std::string imports;
      client.read_stream(imports);

      auto j = nlohmann::json::parse(message);

      if (!j.contains("alloc") || !j.contains("id") || !j.contains("x64")) {
        io::logger->warn("{} sent invalid json image reponse.", ip);

        client_server.disconnect_event.call(client);
        return;
      }

      uintptr_t alloc = j["alloc"];
      std::string id = j["id"];
      bool x64 = j["x64"];

      io::logger->info("{} allocated at {:x}", client.username, alloc);

      if (x64) {
        auto it = client_server.images64.find(id);
        if (it == client_server.images64.end()) {
          io::logger->warn("{} sent invalid game id.");

          client_server.disconnect_event.call(client);
          return;
        }
        auto& img = it->second;

        std::vector<char> image;
        img.copy(image);
        img.relocate(image, alloc);
        img.fix_imports(image, imports);

        client.write(tcp::packet_t("ready", tcp::packet_type::write, session,
                                   tcp::packet_id::image));

        if (client.stream(image) == image.size()) {
          io::logger->info("sent image to {}.", client.username);
        }

        client.state = tcp::client_state::injected;
      } else {
        auto it = client_server.images.find(id);
        if (it == client_server.images.end()) {
          io::logger->warn("{} sent invalid game id.");

          client_server.disconnect_event.call(client);
          return;
        }
        auto& img = it->second;

        std::vector<char> image;
        img.copy(image);
        img.relocate(image, alloc);
        img.fix_imports(image, imports);

        client.write(tcp::packet_t("ready", tcp::packet_type::write, session,
                                   tcp::packet_id::image));

        if (client.stream(image) == image.size()) {
          io::logger->info("sent image to {}.", client.username);
        }

        client.state = tcp::client_state::injected;
      }
    }

    // client.write(tcp::packet_t(message, tcp::packet_type::write, session));
  });

  client_server.timeout_event.add([&](tcp::client& client) {
    client.cleanup();

    auto it = std::find_if(
        client_server().begin(), client_server().end(),
        [&](tcp::client& c) { return c.get_socket() == client.get_socket(); });

    if (it != client_server().end()) {
      client_server().erase(it);
    }

    if (client.security_timeout()) {
      io::logger->warn("{} failed to send security packet in time, dropping...",
                       client.get_ip());
    }

    io::logger->info("{} timed out.", client.get_ip());
  });

  commands cmds;
  cmds.add("reload", [&]() {
    for (auto& [key, image] : client_server.images) {
      image.reload();
    }

    for (auto& [key, image] : client_server.images64) {
      image.reload();
    }
  });

  std::thread t1{[&](tcp::server& srv) {
                   while (srv) {
                     std::string cmd;
                     getline(std::cin, cmd);
                     if (!cmds.parse_input(cmd)) {
                       io::logger->warn("invalid command.");
                     }
                   };
                 },
                 std::ref(client_server)};
  t1.detach();

  std::thread t{tcp::server::monitor, std::ref(client_server)};
  t.join();
}
