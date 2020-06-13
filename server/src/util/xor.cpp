#include "../include.h"
#include "xor.h"

char enc::gen_key() {
  std::random_device r;

  std::default_random_engine e1(r());
  std::uniform_real_distribution<> uniform_dist(0, 255);
  return static_cast<char>(uniform_dist(e1));
}

void enc::encrypt_message(std::string &str) {
  std::array<char, key_len> keys;
  for (size_t i = 0; i < key_len; i++) {
    keys[i] = gen_key();
    str.insert(str.end(), keys[i]);
  }

  for (auto &key : keys) {
    for (size_t i = 0; i < str.size() - key_len; i++) {
      str[i] ^= key;
    }
  }
}

void enc::decrypt_message(std::string &str) {
  if (str.size() <= key_len) return;

  std::string keys = str.substr(0, key_len);
  std::reverse(keys.begin(), keys.end());

  for (auto &key : keys) {
    for (size_t i = key_len; i < str.size(); i++) {
      str[i] ^= key;
    }
  }

  str.erase(str.begin(), str.begin() + key_len);
}