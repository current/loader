#include "../include.h"
#include "../util/io.h"
#include "client.h"

bool tcp::client::init_ssl(SSL_CTX* server_ctx) {
  m_ssl = SSL_new(server_ctx);
  if (!m_ssl) {
    io::logger->error("failed to create ssl on {}.", m_ip);
    return false;
  }

  int ret = SSL_set_fd(m_ssl, m_socket);
  if (ret <= 0) {
    io::logger->error("failed to set descriptor on {}.", m_ip);
    return false;
  }

  ret = SSL_accept(m_ssl);

  if (ret <= 0) {
    int err = SSL_get_error(m_ssl, ret);
    io::logger->error("{} failed to accept ssl, return code {}.", m_ip, err);
    return false;
  }

  return true;
}

void tcp::client::gen_session() {
  std::random_device r;
  std::default_random_engine e1(r());
  std::uniform_int_distribution<int> gen(33, 126);

  for (int i = 0; i < session_id_len; i++) {
    auto k = static_cast<char>(gen(e1));
    m_session_id.insert(m_session_id.end(), k);
  }
}

int tcp::client::stream(std::vector<char>& data, float* dur /*= nullptr*/) {
  auto size = data.size();

  auto networked_size = htonl(size);
  write(&networked_size, sizeof(networked_size));

  // with 4kb chunk size, speed peaks at 90mb/s without enc
  // speed is at ~75mb/s with xor
  constexpr size_t chunk_size = 4096;
  size_t sent = 0;

  auto start = std::chrono::steady_clock::now();
  while (size > 0) {
    auto to_send = std::min(size, chunk_size);

    int ret = write(&data[sent], to_send);
    if (ret <= 0) {
      break;
    }
    sent += ret;
    size -= ret;
  }

  auto end = std::chrono::steady_clock::now();
  std::chrono::duration<float> time = end - start;
  if (dur) *dur = time.count();

  return sent;
}

int tcp::client::read_stream(std::vector<char>& out) {
  size_t size;
  read(&size, sizeof(size));

  size = ntohl(size);
  out.resize(size);

  constexpr size_t chunk_size = 4096;
  size_t total = 0;

  while (size > 0) {
    auto to_read = std::min(size, chunk_size);

    int ret = read(&out[total], to_read);
    if (ret <= 0) {
      break;
    }

    size -= ret;
    total += ret;
  }

  return total;
}