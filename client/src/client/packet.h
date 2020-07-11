#pragma once
#include "enc.h"

#include <json.hpp>

namespace tcp {
constexpr size_t session_id_len = 10;
constexpr size_t message_len = 512;

enum packet_type : int { write = 0, read };

enum packet_id : int { message = 0, hwid, session };

struct packet_t {
  std::string message;
  std::string session_id;
  int id;
  int seq;

  packet_t() {}
  packet_t(const std::string_view msg, const packet_type &type,
           std::string_view session = "",
           const packet_id &action = packet_id::message) {
    if (type == read) {
      ++seq;

      message = msg;
      enc::decrypt_message(message);

      auto json = nlohmann::json::parse(message);

      id = json["id"];
      message = json["message"];
      session_id = json["session_id"];
    } else {
      nlohmann::json json;
      json["id"] = action;
      json["session_id"] = session;
      json["message"] = msg.data();

      message = json.dump();
      session_id = session;
      id = action;

      enc::encrypt_message(message);
    }
  }

  ~packet_t() {
    message.clear();
    session_id.clear();
    id = -1;
  }

  operator bool() const {
    return !message.empty() && !session_id.empty() && id != -1;
  }
  auto &operator()() { return message; }
};
};  // namespace tcp
