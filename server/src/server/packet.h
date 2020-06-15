#pragma once

namespace tcp {
constexpr size_t uid_len = 10;

enum packet_type : int { write = 0, read };

struct packet_t {
  std::string message;
  char action;
  std::string uid;

  packet_t() {}
  packet_t(const std::string msg, const packet_type &type, std::string userid = "") {
    if (type == read) {
      if (msg.size() < uid_len) {
        io::logger->error("client packet message invalid!");
        return;
      }

      uid = msg.substr(0, uid_len);

      action = msg[uid_len];
      message = msg.substr(uid_len);
    } else {
      uid = userid;

      message = fmt::format("{}{}", uid, msg);
    }
  }

  

  operator bool() const {
    return !message.empty() && !uid.empty();
  }
};
};  // namespace tcp
