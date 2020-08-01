#pragma once

class apiset {
	std::unordered_map<std::string, std::string> m_apimap;
public:
	apiset();

	bool find(std::string &mod) {
		auto it = std::find_if(m_apimap.begin(), m_apimap.end(), [&](const std::pair<std::string, std::string>& pair) {
			return mod.find(pair.first) != std::string::npos;
		});

		if (it != m_apimap.end()) {
			mod = it->second;
			return true;
		}
		return false;
	}

	auto &map() { return m_apimap; }
};

extern apiset g_apiset;