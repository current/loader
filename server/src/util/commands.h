#pragma once

class commands {
  using func = std::function<void()>;
  std::unordered_map<std::string_view, func> m_cmds;

 public:
  bool parse_input(const std::string_view str) {
    auto it = m_cmds.find(str);
    if (it != m_cmds.end()) {
      it->second();
      return true;
    }
    return false;
  }

  void add(const std::string_view cmd, const func& cb) { m_cmds[cmd] = cb; }
};
