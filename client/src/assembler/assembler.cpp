#include "../include.h"
#include "assembler.h"

void assembler::start() {}

void assembler::push(const std::vector<uintptr_t>& args) {
  if (!m_x64) {
    for (auto it = args.rbegin(); it != args.rend(); ++it) {
      m_assembler.push(*it);
    }
    return;
  }
  
  // 64bit impl
}

void assembler::call(const uintptr_t addr) {}

void assembler::end() {
  if (m_x64) {
  }

  void* func;
  m_runtime.add(&func, &m_code);

  const size_t size = m_code.codeSize();

  m_buf.resize(size);

  std::memcpy(&m_buf[0], func, size);
}