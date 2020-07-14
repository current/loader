#pragma once
#include <cpr/cpr.h>
#include <json.hpp>
// XenForo forum api wrapper

struct user_data {
  std::string hwid;
  bool banned;
  bool active;
  int id;
};

enum forum_response { api_fail = 0, api_error, api_timeout, api_success };

class xenforo_forum {
  std::string m_link;
  std::string m_api;

  cpr::Header m_header;

 public:
  void init(const std::string_view link, const std::string_view key);
  int check_login(const std::string_view username,
                  const std::string_view password, user_data &data);
  bool edit(const int uid, const std::string_view field,
            const std::string_view val);
};