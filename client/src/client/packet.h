#pragma once
#include "enc.h"

#include <json.hpp>

namespace tcp {
constexpr size_t session_id_len = 10;
constexpr size_t message_len = 1024;

enum packet_type : int { write = 0, read };

struct packet_t {
  std::string message;
  std::string session_id;
  int id;

  packet_t() {}
  packet_t(const std::string_view msg, const packet_type& type,
           std::string_view session = "") {
    if (type == read) {
      ++id;

      message = msg;
      enc::decrypt_message(message);

      auto json = nlohmann::json::parse(message);
      message = json["message"];
      session_id = json["session_id"];

    } else {
      nlohmann::json json;
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
  }

  operator bool() const { return !message.empty() && !session_id.empty(); }
  auto &operator()() { return message; }
};
};  // namespace tcp
