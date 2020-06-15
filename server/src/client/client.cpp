#include "../include.h"
#include "../util/io.h"
#include "client.h"

bool tcp::client::init_ssl(SSL_CTX *server_ctx) {
  m_ssl = SSL_new(server_ctx);
  if (!m_ssl) {
    io::logger->error("failed to create ssl on client {}.", m_ip);
    return false;
  }

  int ret = SSL_set_fd(m_ssl, m_socket);
  if (ret <= 0) {
    io::logger->error("failed to set descriptor on client {}.", m_ip);
    return false;
  }

  ret = SSL_accept(m_ssl);

  long result = SSL_get_verify_result(m_ssl);

  auto str = X509_verify_cert_error_string(result);
  io::logger->info("verify returned {}", str);

  if (ret <= 0) {
    int err = SSL_get_error(m_ssl, ret);
    io::logger->error("client {} failed to accept ssl, return code {}", m_ip,
                     err);
    return false;
  }

  return true;
}

int tcp::client::stream(std::vector<char> &data) {
    auto size = data.size();

    auto networked_size = htonl(size);
    write(&networked_size, sizeof(networked_size));

    // with 4kb chunk size, speed peaks at 90mb/s
    constexpr size_t chunk_size = 4096;
    size_t sent = 0;

    while(size > 0) {
      auto to_send = std::min(size, chunk_size);

      int ret = write(&data[sent], to_send);
      if(ret <= 0) {
        break;
      }

      sent += ret;
      size -= ret;
    }

    return sent;
  }

  int tcp::client::read_stream(std::vector<char> &out) {
    size_t size;
    read(&size, sizeof(size));

    size = ntohl(size);
    out.resize(size);

    constexpr size_t chunk_size = 4096;
    size_t total = 0;
    
    while(size > 0) {
      auto to_read = std::min(size, chunk_size);

      int ret = read(&out[total], to_read);
      if(ret <= 0) {
        break;
      }

      size -= ret;
      total += ret;
    }

    return total;
  }