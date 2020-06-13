#include "../include.h"
#include "xor.h"

char enc::gen_key() {
  std::random_device r;

  std::default_random_engine e1(r());
  std::uniform_real_distribution<> uniform_dist(0, 255);
  return static_cast<char>(uniform_dist(e1));
}

// XOR keys at the beginning of the message for clients
void enc::encrypt_message(std::string &str) {
  std::array<char, key_num> keys;
  for (size_t i = 0; i < key_num; i++) {
    char key = gen_key();
    keys[i] = key;
    str.insert(str.begin(), key);
  }

  for (auto &key : keys) {
    for (size_t i = key_num; i < str.size(); i++) {
      str[i] ^= key;
    }
  }
}

// XOR keys at the end of the message for server messages
void enc::decrypt_message(std::string &str) {
  if (str.size() <= 50) return;

  std::string keys = str.substr(str.size() - key_num);

  for (auto &key : keys) {
    for (size_t i = 0; i < str.size() - key_num; i++) {
      str[i] ^= key;
    }
  }

  str.erase(str.end() - key_num, str.end());
}