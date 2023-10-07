#pragma once

#include <format>
#include <iostream>

using u8 = __UINT8_TYPE__;
using u32 = __UINT32_TYPE__;
using u64 = __UINT64_TYPE__;

constexpr u64 word_size = 8;
using word_t = u64;
static_assert(sizeof(long) == word_size);

constexpr u64 SYS_control_register_function = 0x37714;
constexpr u64 SYS_control_fork_status = 0x37715;

template <class... Args>
void println(std::format_string<Args...> fmt, Args&&... args) {
  std::string line = std::format<Args...>(fmt, std::forward<Args>(args)...);
  std::cout << line << std::endl;
}

template <class... Args>
[[noreturn]] void panic(std::format_string<Args...> fmt, Args&&... args) {
  std::string line = std::format<Args...>(fmt, std::forward<Args>(args)...);
  std::cerr << line << std::endl;
  abort();
}

#define ensure(syscall)                                                            \
  ({                                                                               \
    auto return_value = syscall;                                                   \
    if (return_value == -1) {                                                      \
      panic(#syscall " failed with errno={} at {}:{}", errno, __FILE__, __LINE__); \
    }                                                                              \
    return_value;                                                                  \
  })
