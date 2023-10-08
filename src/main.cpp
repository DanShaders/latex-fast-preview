#include <algorithm>
#include <cassert>
#include <cstring>
#include <filesystem>
#include <format>
#include <iostream>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>
#include <vector>

#include "common.h"

using namespace std::literals;

std::string read_cstring(pid_t child, word_t ptr) {
  static constexpr size_t buffer_size = 256;
  char buffer[buffer_size];

  std::string result;
  while (true) {
    iovec local_buffer[] = {{.iov_base = buffer, .iov_len = buffer_size}};
    iovec remote_buffer[] = {{.iov_base = reinterpret_cast<void*>(ptr), .iov_len = buffer_size}};
    ssize_t count = ensure(process_vm_readv(child, local_buffer, 1, remote_buffer, 1, 0));
    assert(count > 0);

    ssize_t to_copy = 0;
    for (; to_copy < count; ++to_copy) {
      if (buffer[to_copy] == 0) {
        break;
      }
    }

    result += std::string_view{buffer, buffer + to_copy};
    if (to_copy != count) {
      break;
    }
    ptr += to_copy;
  }

  return result;
}

class GenericTracer {
public:
  GenericTracer(int child_) : child(child_) {}

  void run() {
    assert(wait_for_child() == stop_sig_trap);
    set_ptrace_options(DeliverForkNotifications::No);
    resume_child();

    bool inside_syscall = false;

    while (true) {
      auto status = wait_for_child();

      if (status.is_signal_delivery_stop()) {
        resume_child_with_signal(status);
        continue;
      }

      if (status.is_exit()) {
        break;
      }

      if (status == stop_syscall) {
        inside_syscall ^= 1;
        if (inside_syscall == false) {
          auto registers = get_registers();
          if (handle_syscall(registers.orig_rax, registers)) {
            set_registers(registers);
          }
        }
      } else if (status == stop_fork_notification) {
        long pid;
        ptrace(PTRACE_GETEVENTMSG, child, 0, &pid);
        handle_fork_notification(static_cast<pid_t>(pid));
      } else {
        assert(status.type == InterruptStatus::Type::Stopped);
      }

      resume_child();
    }
  }

protected:
  struct InterruptStatus {
    enum class Type {
      Exited,
      Signaled,
      Stopped,
      Continued,
    } type;
    int code = -1;
    bool is_fork = false;

    bool operator==(InterruptStatus const& other) const = default;

    bool is_exit() {
      return type == Type::Exited || type == Type::Signaled;
    }

    bool is_signal_delivery_stop() {
      // FIXME: Align with man page.
      return type == Type::Stopped && code != stop_syscall.code && !is_fork;
    }
  };

  enum class DeliverForkNotifications {
    Yes,
    No,
  };

  inline static constexpr InterruptStatus stop_sig_trap = {
      .type = InterruptStatus::Type::Stopped,
      .code = SIGTRAP,
      .is_fork = false,
  };

  inline static constexpr InterruptStatus stop_sig_stop = {
      .type = InterruptStatus::Type::Stopped,
      .code = SIGSTOP,
      .is_fork = false,
  };

  inline static constexpr InterruptStatus stop_syscall = {
      .type = InterruptStatus::Type::Stopped,
      .code = SIGTRAP | 0x80,
      .is_fork = false,
  };

  inline static constexpr InterruptStatus stop_fork_notification = {
      .type = InterruptStatus::Type::Stopped,
      .code = SIGTRAP,
      .is_fork = true,
  };

  virtual bool handle_syscall(u64 syscall_number, user_regs_struct& registers) = 0;
  virtual void handle_fork_notification(pid_t forked_process_pid) = 0;

  InterruptStatus wait_for_child(pid_t pid = -1) {
    if (pid == -1) {
      pid = child;
    }

    int status;
    assert(ensure(waitpid(pid, &status, 0)) == pid);

    InterruptStatus result{};
    if (WIFEXITED(status)) {
      result.type = InterruptStatus::Type::Exited;
      result.code = WEXITSTATUS(status);
    } else if (WIFSTOPPED(status)) {
      result.type = InterruptStatus::Type::Stopped;
      result.code = WSTOPSIG(status);
      result.is_fork = (status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK << 8)));
    } else if (WIFCONTINUED(status)) {
      result.type = InterruptStatus::Type::Continued;
      result.code = -1;
    } else if (WIFSIGNALED(status)) {
      result.type = InterruptStatus::Type::Signaled;
      result.code = WTERMSIG(status);
    } else {
      assert(false);
    }
    return result;
  }

  void resume_child() {
    ensure(ptrace(PTRACE_SYSCALL, child, 0, 0));
  }

  void resume_child_with_signal(InterruptStatus status) {
    assert(status.is_signal_delivery_stop());
    ptrace(PTRACE_SYSCALL, child, 0, status.code);
  }

  user_regs_struct get_registers() {
    user_regs_struct registers;
    ensure(ptrace(PTRACE_GETREGS, child, 0, &registers));
    return registers;
  }

  void set_registers(user_regs_struct const& registers) {
    ensure(ptrace(PTRACE_SETREGS, child, 0, &registers));
  }

  void set_ptrace_options(DeliverForkNotifications deliver_fork_notifications) {
    u64 flags = PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD;
    if (deliver_fork_notifications == DeliverForkNotifications::Yes) {
      flags |= PTRACE_O_TRACEFORK;
    }
    ensure(ptrace(PTRACE_SETOPTIONS, child, 0, flags));
  }

  int child;
};

class Tracer : public GenericTracer {
public:
  using GenericTracer::GenericTracer;

protected:
  bool handle_syscall(u64 syscall_number, user_regs_struct& registers) override {
    if (syscall_number == SYS_control_register_function) {
      at_fork_function = registers.rdi;
    } else if (syscall_number == SYS_openat) {
      if (read_cstring(child, registers.rsi) == "test/content.tex") {
        saved_registers = registers;
        assert(at_fork_function != 0);

        registers.rsp &= ~static_cast<u64>(15);
        registers.rsp -= 8;
        registers.rip = at_fork_function;

        set_ptrace_options(DeliverForkNotifications::Yes);
        return true;
      }
    } else if (syscall_number == SYS_control_fork_status) {
      auto current = std::chrono::system_clock::now();
      println("child exited with code={} {}s", registers.rdi,
              std::chrono::duration<double>(current - previous).count());
      if (previous != std::chrono::system_clock::time_point{}) {
        exit(0);
      }
      previous = current;

      registers.rax = 0;
      return true;
    }
    return false;
  }

  void handle_fork_notification(pid_t forked_process_pid) override {
    assert(wait_for_child(forked_process_pid) == stop_sig_stop);
    ptrace(PTRACE_SETREGS, forked_process_pid, 0, &saved_registers);
    ptrace(PTRACE_DETACH, forked_process_pid, 0, 0);
  }

  user_regs_struct saved_registers;
  u64 at_fork_function = 0;

  std::chrono::system_clock::time_point previous;
};

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
    Tracer(child).run();
  }
}
