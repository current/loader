#include "../include.h"
#include "client.h"

bool tcp::client::start(const std::string_view server_ip,
                        const uint16_t &port) {
#ifdef WINDOWS
  WSADATA data;
  int res = WSAStartup(MAKEWORD(2, 2), &data);
  if (res != 0) {
    io::logger->error("failed to initialize WSA.");
    return false;
  }
#endif

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

  return true;
}
