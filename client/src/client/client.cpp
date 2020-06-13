#include "../include.h"
#include "client.h"

bool tcp::client::start(const std::string_view server_ip,
                        const uint16_t port) {
  SSL_library_init();

  m_ssl_ctx = SSL_CTX_new(TLS_client_method());

  m_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (m_socket == -1) {
    io::logger->error("failed to create socket.");
    return false;
  }

  sockaddr_in server_addr;

  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr(server_ip.data());
  server_addr.sin_port = htons(port);

  int ret = connect(m_socket, reinterpret_cast<sockaddr *>(&server_addr),
                    sizeof(server_addr));
  if (ret < 0) {
    io::logger->error("failed to connect to server.");
    return false;
  }

  m_server_ssl = SSL_new(m_ssl_ctx);
  SSL_set_fd(m_server_ssl, m_socket);

  ret = SSL_connect(m_server_ssl);
  if(ret != 1) {
    ret = SSL_get_error(m_server_ssl, ret);
    io::logger->error("failed to connect to server ssl. {}", ret);
    return false;
  }

  return true;
}
