#include "../include.h"
#include "../util/io.h"
#include "server.h"

bool tcp::server::start(const std::string_view port) {
  io::logger->info("starting server on port {}...", port.data());

  m_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (m_socket < 0) {
    io::logger->critical("failed to create socket.");
    return false;
  }
  struct addrinfo hints, *addrinfo = nullptr;

  memset(&hints, 0, sizeof hints);

  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;

  int ret = getaddrinfo(nullptr, port.data(), &hints, &addrinfo);
  if (ret != 0) {
    io::logger->critical("failed to get address info.");
    close(m_socket);
    return false;
  }

  ret = bind(m_socket, addrinfo->ai_addr, addrinfo->ai_addrlen);
  if (ret < 0) {
    io::logger->critical("failed to bind port.");
    close(m_socket);
    return false;
  }
  io::logger->info("port bound.");
  freeaddrinfo(addrinfo);

  ret = listen(m_socket, SOMAXCONN);
  if (ret < 0) {
    io::logger->critical("failed to listen on port {}.", port.data());
    close(m_socket);
    return false;
  }
  io::logger->info("listening on {}.", port.data());

  return true;
}

void tcp::server::stop() {
	io::logger->info("stopping server on port {}.", m_port);
	close(m_socket);
}