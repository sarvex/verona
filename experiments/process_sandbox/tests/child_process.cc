// Copyright Microsoft and Project Verona Contributors.
// SPDX-License-Identifier: MIT
#include <platform/platform.h>
#include <thread>

using namespace sandbox::platform;

template<typename Child>
void test_child()
{
  Child cp([]() {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    exit(2);
  });
  auto ec = cp.wait_for_exit();
  assert(ec.has_exited);
  assert(ec.exit_code == 2);
  auto ec2 = cp.exit_status();
  assert(ec2.has_exited);
  assert(ec2.exit_code == 2);
}

using Fallback =
#ifdef __unix__
  ChildProcessVFork
#else
  ChildProcess
#endif
  ;

int main(void)
{
  test_child<ChildProcess>();
  if (!std::is_same_v<ChildProcess, Fallback>)
  {
    test_child<Fallback>();
  }
}
