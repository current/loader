#pragma once

class blacklist {
  nlohmann::json m_data;
  std::string m_name;

 public:
  void init(const std::string_view file = "blacklist") {
    m_name = file;

    std::string data;
    if (!io::read_file(file, data)) return;

    if (!nlohmann::json::accept(data)) {
      io::logger->error("blacklist file isnt valid json.");
      return;
    }

    m_data = nlohmann::json::parse(data);
  }

  void add(const uint32_t hwid) {
    m_data["hwids"].emplace_back(hwid);

    save();
  }

  void save() {
    std::ofstream o(m_name, std::ios::trunc);
    o << std::setw(4) << m_data;
    o.close();
  }

  bool find(const uint32_t key) {
    for (auto &item : m_data["hwids"]) {
      if (item.get<uint32_t>() == key) {
        return true;
      }
    }
    return false;
  }
};
