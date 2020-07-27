#include "../include.h"
#include "io.h"

bool io::read_file(const std::string_view name, std::vector<char>& out) {
	std::ifstream file(name.data(), std::ios::binary);
	if (!file.good()) {
		log_error("{} isnt valid.", name);
		return false;
	}

	file.unsetf(std::ios::skipws);

	file.seekg(0, std::ios::end);
	const size_t size = file.tellg();
	file.seekg(0, std::ios::beg);

	out.resize(size);

	file.read(&out[0], size);

	file.close();

	return true;
}
