#include <cassert>
#include <cstring>
#include <filesystem>
#include <format>
#include <iostream>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>
#include <vector>

#include "common.h"

using namespace std::literals;

auto read_at(pid_t child, word_t ptr) {
  u64 aligned_ptr = ptr & ~(word_size - 1);

  union {
    word_t as_word;
    char as_bytes[word_size];
  } data;
  errno = 0;
  data.as_word = ptrace(PTRACE_PEEKTEXT, child, aligned_ptr, 0);
  if (errno) {
    ensure(-1);
  }

  std::pair<size_t, std::array<char, word_size>> result;
  result.first = word_size - (ptr - aligned_ptr);
  for (size_t i = 0; i < result.first; ++i) {
    result.second[i] = data.as_bytes[i + (ptr - aligned_ptr)];
  }
  return result;
}

std::string read_cstring(pid_t child, word_t ptr) {
  std::string result;
  while (true) {
    auto [count, bytes] = read_at(child, ptr);
    ptr += count;

    size_t to_copy = 0;
    for (; to_copy < count; ++to_copy) {
      if (bytes[to_copy] == 0) {
        break;
      }
    }
    result += std::string_view{bytes.begin(), bytes.begin() + to_copy};
    if (to_copy != count) {
      break;
    }
  }
  return result;
}

int main() {
  char const* const arguments[] = {
      "/usr/bin/latex",
      "-interaction=nonstopmode",
      "test/main.tex",
      nullptr,
  };

  auto ld_preload_str =
      std::format("LD_PRELOAD={}/build/libinjected.so", std::filesystem::current_path().c_str());
  std::vector<char const*> environment;
  environment.push_back(ld_preload_str.data());
  for (char** var = environ; *var != nullptr; ++var) {
    environment.push_back(*var);
  }
  environment.push_back(nullptr);

  int child = ensure(fork());
  if (child == 0) {
    ensure(ptrace(PTRACE_TRACEME, 0, 0, 0));
    ensure(execve(arguments[0], const_cast<char* const*>(arguments),
                  const_cast<char* const*>(environment.data())));
  } else {
    int status;
    ensure(waitpid(child, &status, 0));
    assert(WIFSTOPPED(status) && WSTOPSIG(status) == 5);

    ensure(ptrace(PTRACE_SETOPTIONS, child, 0,
                  PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK));

    ensure(ptrace(PTRACE_SYSCALL, child, 0, 0));

    user_regs_struct regs, saved_regs;
    u64 at_fork_function = 0;
    bool suspended_before_fork = false;
    pid_t process;

    while ((process = ensure(waitpid(child, &status, 0)))) {
      if (process != child) {
        ensure(ptrace(PTRACE_DETACH, process, 0, 0));
        continue;
      }

      if (WIFEXITED(status) || WIFSIGNALED(status)) {
        assert(false);
      }

      assert(WIFSTOPPED(status));
      if (WSTOPSIG(status) == (SIGTRAP | 0x80)) {
        ensure(ptrace(PTRACE_GETREGS, child, 0, &regs));

        ensure(ptrace(PTRACE_SYSCALL, child, 0, 0));
        ensure(waitpid(child, &status, 0));
        assert(WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80));

        if (regs.orig_rax == SYS_control_register_function) {
          assert(at_fork_function == 0);
          at_fork_function = regs.rdi;
          regs.rax = 0;
          ensure(ptrace(PTRACE_SETREGS, child, 0, &regs));
        } else if (regs.orig_rax == SYS_openat) {
          if (read_cstring(child, regs.rsi) == "test/content.tex") {
            ensure(ptrace(PTRACE_GETREGS, child, 0, &regs));
            saved_regs = regs;

            if ((regs.rsp & 15) != 0) {
              regs.rsp &= ~static_cast<u64>(15);
            }
            regs.rsp -= 8;
            regs.rip = at_fork_function;
            ensure(ptrace(PTRACE_SETREGS, child, 0, &regs));
            suspended_before_fork = true;
            break;
          }
        }
      } else if (WSTOPSIG(status) != SIGTRAP && WSTOPSIG(status) != SIGSTOP) {
        ptrace(PTRACE_DETACH, child, 0, 0);
        continue;
      }
      ensure(ptrace(PTRACE_SYSCALL, child, 0, 0));
    }

    assert(suspended_before_fork);

    for (int i = 0; i < 10; ++i) {
      ensure(ptrace(PTRACE_SYSCALL, child, 0, 0));

      while (ensure(waitpid(child, &status, 0)) && (status >> 16 != PTRACE_EVENT_FORK)) {
        assert(WIFSTOPPED(status) && (WSTOPSIG(status) == (SIGTRAP | 0x80) ||
                                      WSTOPSIG(status) == SIGSTOP || WSTOPSIG(status) == SIGCHLD));
        ptrace(PTRACE_SYSCALL, child, 0, 0);
      }

      std::string s;
      getline(std::cin, s);

      word_t worker_pid = 0;
      ensure(ptrace(PTRACE_GETEVENTMSG, child, 0, &worker_pid));

      ensure(waitpid(worker_pid, &status, 0));
      ensure(ptrace(PTRACE_SETREGS, worker_pid, 0, &saved_regs));
      ensure(ptrace(PTRACE_DETACH, worker_pid, 0, 0));
    }
  }
}
