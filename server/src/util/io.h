#pragma once

namespace io {
    extern std::shared_ptr<spdlog::logger> logger;

    void init(const bool& to_file);
    void read_file(const std::string_view name, std::vector<char>& out);
}; // namespace io
