#include "../include.h"
#include "util.h"


void util::to_lowercase(std::string &str) {
	std::transform(str.begin(), str.end(), str.begin(), ::tolower);
}


