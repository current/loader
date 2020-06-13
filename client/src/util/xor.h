#pragma once

namespace enc {
constexpr size_t key_num = 50;

char gen_key();

// XOR keys at the beginning of the message for clients
void encrypt_message(std::string &str);

// XOR keys at the end of the message for server messages
void decrypt_message(std::string &str);

}  // namespace enc