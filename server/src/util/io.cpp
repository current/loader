#include "../include.h"
#include "io.h"

std::shared_ptr<spdlog::logger> io::logger;

void io::init(const bool& to_file) {
  auto sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
  sink->set_pattern("[%R][%^%l%$] %v");

  auto file_sink =
      std::make_shared<spdlog::sinks::basic_file_sink_mt>("server.log", true);

  std::vector<spdlog::sink_ptr> log_sinks;
  log_sinks.emplace_back(sink);

  if (to_file) log_sinks.emplace_back(file_sink);

  logger = std::make_shared<spdlog::logger>("server", log_sinks.begin(),
                                            log_sinks.end());
  spdlog::register_logger(logger);

  spdlog::flush_every(std::chrono::seconds(1));
}

bool io::read_file(const std::string_view name, std::vector<char>& out) {
  std::ifstream file(name.data(), std::ios::binary);
  if (!file.good()) {
    return false;
  }

  file.unsetf(std::ios::skipws);

  file.seekg(0, std::ios::end);
  const size_t size = file.tellg();
  file.seekg(0, std::ios::beg);

  out.resize(size);

  file.read(out.data(), size);

  file.close();

  return true;
}

bool io::read_file(const std::string_view name, std::string& out) {
  std::vector<char> vec;
  if(!read_file(name, vec))
    return false;

  out.assign(vec.begin(), vec.end());

  return true;
}
