#pragma once

namespace tcp {
class server {
  int m_socket;
  
 public:

  bool start(const std::string_view port);
  void stop();
};
};  // namespace tcp
