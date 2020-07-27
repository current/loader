#include "../include.h"
#include "../util/io.h"
#include "forum.h"

void xenforo_forum::init(const std::string_view link,
                         const std::string_view key) {
  m_link = link;
  m_api = key;

  m_header = cpr::Header{{"Content-Type", "application/x-www-form-urlencoded"},
                         {"XF-Api-Key", m_api.data()},
                         {"XF-Api-User", "1"},
                         {"api_bypass_permissions", "1"}};
}

int xenforo_forum::check_login(const std::string_view username,
                               const std::string_view password,
                               user_data &data) {
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
    io::logger->error("invalid json response from forum.", username);
    return forum_response::api_fail;
  }

  if (status_code >= 400) {
    return forum_response::api_error;
  }

  auto json = nlohmann::json::parse(response);

  if (!json.contains("user")) {
    io::logger->error("json response for user {} doesn't contain user field.",
                      username);
    return forum_response::api_fail;
  }

  auto user = json["user"];

  if (!user.contains("custom_fields")) {
    io::logger->error(
        "json response for user {} doesn't contain custom fields.", username);
    return forum_response::api_fail;
  }

  auto custom_fields = user["custom_fields"];

  if(!user.contains("is_banned")) {
    io::logger->error(
        "json response for user {} doesn't contain is_banned.", username);
    return forum_response::api_fail;
  }

  data.banned = user["is_banned"].get<bool>();

  if(!user.contains("user_id")) {
    io::logger->error(
        "json response for user {} doesn't contain user_id.", username);
    return forum_response::api_fail;
  }

  data.id = user["user_id"].get<int>();

  if(!custom_fields.contains("hwid")) {
    io::logger->error("custom fields for user {} dont contain hwid.", username);
    return forum_response::api_fail;
  }

  // data.active = check user group
  data.hwid = custom_fields["hwid"].get<std::string>();

  return forum_response::api_success;
}

bool xenforo_forum::edit(const int uid, const std::string_view field,
                         const std::string_view val) {
  const auto url = fmt::format("{}{}{}/", m_link, "/users/", uid);
  const auto post = fmt::format("{}={}", field, val);

  auto req =
      cpr::Post(cpr::Url{url}, cpr::Body{post}, cpr::Timeout{10000}, m_header);
  return req.status_code == 200;
}