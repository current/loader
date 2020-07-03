#pragma once

#include <asmjit/src/asmjit/asmjit.h>

using namespace asmjit;

namespace assembler {

class assembler {
  std::vector<uint8_t> m_buf;

  CodeHolder m_code;
  JitRuntime m_runtime;
  x86::Assembler m_assembler;

 public:
  assembler(const bool x64 = false) {
    Environment env(x64 ? Environment::kArchX64 : Environment::kArchX86);

    m_code.init(env);
    m_code.attach(&m_assembler);
  }
  void start();
  void push(const std::vector<uintptr_t> &args);
  void call(const uintptr_t addr);
  void save_ret(const uintptr_t addr);
  void end();

  auto &operator()() const { return m_buf; }
  auto &operator->() const { return m_assembler; }
};

};  // namespace assembler