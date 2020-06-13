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
  if (ret <= 0) {
    int err = SSL_get_error(m_ssl, ret);
    io::logger->error("client {} failed to accept ssl, return code {}", m_ip,
                     err);
    return false;
  }

  return true;
}