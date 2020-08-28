#pragma once
#include "enc.h"

#include <json.hpp>

namespace tcp {
constexpr size_t session_id_len = 10;
constexpr size_t message_len = 512;

enum packet_type { write = 0, read };

enum packet_id {
  message = 0,
  hwid,
  hwid_resp,
  session,
  login_req,
  login_resp,
  security_report,
  ban,
  game_select,
  image
};

struct packet_t {
  uint8_t id;
  std::string message;
  std::string session_id;

  packet_t() {}
  packet_t(const std::string_view msg, const packet_type &type,
           std::string_view session = "",
           const packet_id &action = packet_id::message) {
    if (type == read) {
      message = msg;
      enc::decrypt_message(message);

      if (!nlohmann::json::accept(message)) {
        io::logger->error("message isn't valid json");
        return;
      }

      auto json = nlohmann::json::parse(message);
      if (json.contains("id") && json.contains("session_id") &&
          json.contains("message")) {
        id = json["id"];
        session_id = json["session_id"];
        message = json["message"];
      }
    } else {
      nlohmann::json json;
      json["id"] = action;
      json["session_id"] = session;
      json["message"] = msg.data();

      message = json.dump();
      session_id = session;

      enc::encrypt_message(message);
    }
  }

  ~packet_t() {
    message.clear();
    session_id.clear();
    id = -1;
  }

  operator bool() const { return !message.empty() && !session_id.empty(); }
  auto &operator()() { return message; }
};
};  // namespace tcp
