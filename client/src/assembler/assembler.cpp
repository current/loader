#include "../include.h"
#include "assembler.h"

void assembler::assembler::push(const std::vector<uintptr_t>& args) {
  for (auto it = args.rbegin(); it != args.rend(); ++it) {
    m_assembler.push(*it);
  }
}

void assembler::assembler::end() {
  // epilogue here

  void* func;
  m_runtime.add(&func, &m_code);

  const size_t size = m_code.codeSize();

  m_buf.resize(size);

  std::memcpy(&m_buf[0], func, size);
}