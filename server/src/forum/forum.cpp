#include "../include.h"
#include "../util/io.h"
#include "forum.h"

void xenforo_forum::init(const std::string_view link, const std::string_view key) {
	m_link = link;
	m_api = key;

	m_header = cpr::Header{{"Content-Type", "application/x-www-form-urlencoded"},
                         {"XF-Api-Key", m_api.data()},
                         {"XF-Api-User", "1"},
                         {"api_bypass_permissions", "1"}};
}

int xenforo_forum::check_login(const std::string_view username,
                   const std::string_view password, user_data &data) {
	auto url = fmt::format("{}{}", m_link, "/auth/");
  auto post_data = fmt::format("login={}&password={}", username, password);

  auto req = cpr::Post(cpr::Url{url}, cpr::Body{post_data}, cpr::Timeout{10000},
                     m_header);

  if (req.elapsed >= 10) {
    io::logger->warn("login request on {} timed out.", username);
    return forum_response::api_timeout;
  }

  int status_code = req.status_code;
  auto response = req.text;

  if (!nlohmann::json::accept(response)) {
  	io::logger->error("login response on {} isnt valid json.", username);
  	return forum_response::api_fail;
  }

  if (status_code >= 400) {
    return forum_response::api_error;
  }

  auto j = nlohmann::json::parse(response);
  
  data.banned = j["user"]["is_banned"].get<bool>();
  // data.active = check user group
  data.hwid = j["user"]["custom_fields"]["hwid"].get<std::string>();

  return forum_response::api_success;
}