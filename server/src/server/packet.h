#pragma once
#include "enc.h"

#include <json.hpp>

namespace tcp {
constexpr size_t session_id_len = 10;
constexpr size_t message_len = 512;

enum packet_type : int { write = 0, read };

enum packet_action : uint8_t { message = 0, hwid = 1, session };

struct packet_t {
  std::string message;
  std::string session_id;
  uint8_t act;

  packet_t() {}
  packet_t(const std::string_view msg, const packet_type &type,
           std::string_view session = "",
           const packet_action &action = packet_action::message) {
    if (type == read) {
      message = msg;
      enc::decrypt_message(message);

      if (!nlohmann::json::accept(message)) {
        io::logger->error("message isn't valid json");
        return;
      }

      auto json = nlohmann::json::parse(message);
      message = json["message"];
      session_id = json["session_id"];
      act = json["action"];
    } else {
      nlohmann::json json;
      json["action"] = action;
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
    act = -1;
  }

  operator bool() const { return !message.empty() && !session_id.empty(); }
  auto &operator()() { return message; }
};
};  // namespace tcp
