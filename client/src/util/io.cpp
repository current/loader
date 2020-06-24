#include "../include.h"
#include "io.h"

std::shared_ptr<spdlog::logger> io::logger;

void io::init() {
  spdlog::sink_ptr sink =
      std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
  sink->set_pattern("%^~>%$ %v");

  logger = std::make_shared<spdlog::logger>("client", sink);
}
