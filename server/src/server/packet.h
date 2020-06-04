#pragma once

namespace tcp {
  constexpr uint8_t uid_len = 10;

  struct packet_t {
    std::string message;
    std::array<char, uid_len> uid;
  }
}
