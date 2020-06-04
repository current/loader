#pragma once

#if defined(_WIN32) || defined(_WIN64)
#define WINDOWS
#endif

#ifdef WINDOWS
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#pragma comment( lib, "ws2_32.lib" )
#endif

#include <stdio.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <vector>
#include <unordered_map>
#include <optional>
#include <iomanip>
#include <map>
#include <random>
#include <list>
#include <utility>
#include <atomic>
#include <mutex>
#include <future>
#include <any>

#ifndef WINDOWS

#define closesocket(socket) close(socket)

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <spdlog/fmt/fmt.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>