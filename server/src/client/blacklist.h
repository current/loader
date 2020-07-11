#pragma once

namespace tcp {

struct blacklist_data {
	std::string ip;
	std::string hwid;
};

class blacklist {

nlohmann::json m_data;
std::string m_name;

public:
	void init(const std::string_view file = "blacklist") {
		m_name = file;

		std::string data;
		if(!io::read_file(file, data))
			return;

		if(!nlohmann::json::accept(data)) {
			io::logger->error("blacklist file isnt valid json.");
			return;
		}

		m_data = nlohmann::json::parse(data);
	}

	void add(const blacklist_data &data) {
		m_data["ips"].emplace_back(data.ip);
		m_data["hwids"].emplace_back(data.hwid);

		save();
	}

	void save() {
		std::ofstream o(m_name, std::ios::trunc);
		o << std::setw(4) << m_data;
		o.close();
	}

	bool find(const std::string &key) {
		for(auto &item : m_data["ips"]) {
			if(item.get<std::string>() == key) {
				return true;
			}
		}
		return false;
	}
};

}; 