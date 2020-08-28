#include "../include.h"
#include "../util/io.h"
#include "server.h"

void tcp::server::start() {
  m_blacklist.init();

  m_forum.init("", "");

  io::logger->info("starting server on port {}...", m_port.data());

  ssl ctx("ssl/server.crt", "ssl/server.key", "ssl/rootCA.crt");
  if (!ctx.init()) return;

  m_ctx = std::move(ctx.get_context());

  m_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (m_socket < 0) {
    io::logger->critical("failed to create socket.");
    return;
  }

  int enable = 1;
  int ret = setsockopt(m_socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
  if (ret < 0) {
    io::logger->critical("failed to set socket option.");
    return;
  }

  struct addrinfo hints, *addrinfo = nullptr;

  memset(&hints, 0, sizeof hints);

  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;

  ret = getaddrinfo(nullptr, m_port.data(), &hints, &addrinfo);
  if (ret != 0) {
    io::logger->critical("failed to get address info.");
    close(m_socket);
    return;
  }

  ret = bind(m_socket, addrinfo->ai_addr, addrinfo->ai_addrlen);
  if (ret < 0) {
    io::logger->critical("failed to bind port.");
    close(m_socket);
    return;
  }
  io::logger->info("port bound.");
  freeaddrinfo(addrinfo);

  ret = listen(m_socket, SOMAXCONN);
  if (ret < 0) {
    io::logger->critical("failed to listen on port {}.", m_port.data());
    close(m_socket);
    return;
  }
  io::logger->info("listening on {}.", m_port.data());

  m_active = true;
}

tcp::select_status tcp::server::peek() {
  FD_ZERO(&m_server_set);
  FD_SET(m_socket, &m_server_set);

  int maxfd = m_socket;

  for (auto& c : client_stack) {
    const int s = c.get_socket();
    FD_SET(s, &m_server_set);

    maxfd = std::max(maxfd, s);
  }

  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;

  const int ret = select(maxfd + 1, &m_server_set, nullptr, nullptr, &tv);
  if (ret < 0) {
    io::logger->error("select error : {}.", strerror(errno));
    return tcp::select_status::error;
  }

  if (ret == 0) {
    return tcp::select_status::standby;
  }

  return tcp::select_status::ready;
}

void tcp::server::accept_client() {
  if (!FD_ISSET(m_socket, &m_server_set)) return;

  struct sockaddr_in addr;
  socklen_t len = sizeof(addr);
  const int client_socket =
      accept(m_socket, reinterpret_cast<sockaddr*>(&addr), &len);

  const auto ip = inet_ntoa(addr.sin_addr);
  if (client_socket < 0) {
    io::logger->warn("{} failed to accept.", ip);
    close(client_socket);
  } else {
    client cli(client_socket, ip);
    if (!cli.init_ssl(m_ctx)) {
      cli.cleanup();
      return;
    }

    auto it = std::find_if(client_stack.begin(), client_stack.end(),
                           [&](client& c) { return c.get_ip() == ip; });
    if (it != client_stack.end()) {
      io::logger->info("{} is already connected, dropping...", ip);
      cli.cleanup();
      return;
    }
    
    cli.reset();

    connect_event.call(cli);

    client_stack.emplace_back(std::move(cli));
  }
}

void tcp::server::receive() {
  std::array<char, message_len> buf;
  for (auto& c : client_stack) {
    const int socket = c.get_socket();

    if (!FD_ISSET(socket, &m_server_set)) continue;

    buf.fill(0);

    const int read = c.read(&buf[0], buf.size());
    if (read > 0) {
      c.reset();

      std::string msg(buf.data(), read);

      tcp::packet_t packet(msg, tcp::packet_type::read);

      receive_event.call(packet, c);
    } else {
      disconnect_event.call(c);
    }
  }
}

void tcp::server::check_timeout() {
  auto it = std::find_if(client_stack.begin(), client_stack.end(),
                         [&](client& c) { return c.timeout() || c.security_timeout(); });

  if (it != client_stack.end()) {
    timeout_event.call(*it);
  }
}

void tcp::server::stop() {
  io::logger->info("stopping server on port {}.", m_port);
  close(m_socket);
}