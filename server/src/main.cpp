#include "include.h"
#include "util/io.h"
#include "util/commands.h"
#include "server/server.h"

int main(int argc, char *argv[]) {
  io::init(false);

  tcp::server server;
  server.start("6666");
  server.start("8981");

  std::cin.get();
}
