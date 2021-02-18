// Copyright Microsoft and Project Verona Contributors.
// SPDX-License-Identifier: MIT
#include <future>
#include <platform/platform.h>
#include <thread>
#include <unordered_set>
#include <vector>

using namespace sandbox::platform;

// Timeout.  If you are debugging this test, increase this so that it doesn't
// fail in the background while you're inspecting a breakpoint.
constexpr int timeout_seconds = 5;

template<typename Sem>
void test_sem()
{
  Sem sem;
  std::atomic<bool> passed;
  // Spawn another thread spawns a child process that waits with a long
  // timeout.  We spawn the child process in a new thread because there's no
  // requirement that the child is executed in parallel until it calls execve
  // (which doesn't happen here).
  std::thread t([&]() {
    ChildProcess p([&]() { exit(sem.wait(timeout_seconds * 1000)); });
    auto ret = p.wait_for_exit();
    assert(ret.exit_code == 1);
    passed = true;
  });
  sem.wake();

  auto future = std::async(std::launch::async, &std::thread::join, &t);
  // Join or time out after 5 seconds so the test fails if we infinite loop
  assert(
    future.wait_for(std::chrono::seconds(timeout_seconds)) !=
    std::future_status::timeout);
  assert(passed);
}

int main(void)
{
  test_sem<OneBitSem>();
}
