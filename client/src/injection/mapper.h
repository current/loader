#pragma once

namespace mmap {

struct mapper_data_t {
  size_t image_size;
  uint32_t entry;
  uint32_t base;
  std::string imports;
  std::vector<char> image;
};

};  // namespace mmap