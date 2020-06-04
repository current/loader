#pragma once

namespace tcp {
  constexpr size_t uid_len = 10;
  struct packet_t {
    std::string message;
    char action;
    std::array<char, uid_len> uid;

    // parse packet from server message after decryption
    bool parse(const std::string msg) {
      // first 10 bytes is the uid
      bool res = set_uid(msg.substr(0, uid_len));
      if(!res) {
        return false;
      }

      action = msg[uid_len];
      const bool stream = static_cast<bool>(msg[uid_len + 1]);
      if(stream) {
        const size_t size = std::stoll(msg.substr(uid_len + 2));

        // receive stream

        return true;
      }

      message = msg.substr(uid_len + 2);
      return true;
    }
    bool set_uid(const std::string_view uid_str) {
      const size_t uid_str_len = uid_str_len.size();
      if(uid_str_len != uid_len) {
        io::logger->error("packet uid len mismatch!");
        return false;
      }

      for(size_t i = 0; i < uid_len; ++i) {
        uid[i] = uid_str[i];
      }

      return true;
    }
  };
};
