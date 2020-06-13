#pragma once

namespace enc {
constexpr size_t key_len = 50;

char gen_key();

void encrypt_message(std::string &str);

void decrypt_message(std::string &str);

}  // namespace enc