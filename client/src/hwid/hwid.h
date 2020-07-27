#pragma once


namespace hwid {
	__forceinline std::string fetch() {
		nlohmann::json j;
		j["uid"] = 0;
		return j.dump();
	}
};