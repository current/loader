#pragma once
#include "../util/enc.h"

namespace tcp {
constexpr size_t session_id_len = 10;
constexpr size_t message_len = 256 + session_id_len;

enum packet_type : int { write = 0, read };

struct packet_t {
  std::string message;
  char action;
  std::string session_id;
  int id;

  packet_t() {}
  packet_t(const std::string_view msg, const packet_type& type,
           std::string_view session = "") {
    if (type == read) {
      ++id;

      if (msg.size() < session_id_len) {
        io::logger->error("packet message invalid!");
        return;
      }

      message = msg;
      enc::decrypt_message(message);

      session_id = message.substr(0, session_id_len);

      action = message[session_id_len];
      message = message.substr(session_id_len);
    } else {
      session_id = session;

      message = fmt::format("{}{}", session_id, msg);

      if (msg.size() > message_len) {
        io::logger->error("packet message exceeds limit");
        message.clear();
        session_id.clear();
        return;
      }
      enc::encrypt_message(message);
    }
  }

  ~packet_t() {
    message.clear();
    session_id.clear();
  }

  operator bool() const { return !message.empty() && !session_id.empty(); }
};
};  // namespace tcp
