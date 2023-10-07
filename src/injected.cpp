#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#include "common.h"

void at_fork() {
  std::vector<std::pair<int, off_t>> fd_offsets;
  for (auto fd : std::filesystem::recursive_directory_iterator("/proc/self/fd")) {
    int fd_num = atoi(fd.path().filename().c_str());
    off_t offset = lseek(fd_num, 0, SEEK_CUR);
    if (offset != -1) {
      fd_offsets.push_back({fd_num, offset});
    }
  }

  while (true) {
    pid_t pid = ensure(syscall(SYS_fork));

    auto start = std::chrono::system_clock::now();

    assert(pid > 0);
    int status;
    waitpid(pid, &status, 0);
    assert(WIFEXITED(status) || WIFSIGNALED(status));

    auto end = std::chrono::system_clock::now();
    std::cout << "Done in " << std::chrono::duration<double>(end - start).count() << "s"
              << std::endl;

    for (auto [fd, offset] : fd_offsets) {
      lseek(fd, offset, SEEK_SET);
    }
  }
}

[[gnu::constructor]] void on_entry() {
  syscall(SYS_control_register_function, &at_fork);
}
