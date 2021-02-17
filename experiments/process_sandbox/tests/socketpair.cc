// Copyright Microsoft and Project Verona Contributors.
// SPDX-License-Identifier: MIT
#include <platform/platform.h>

using namespace sandbox::platform;

int main(void)
{
  auto sp = SocketPair::create();
  int i = 42;
  assert(write(sp.first.fd, &i, sizeof(i)) == sizeof(i));
  assert(read(sp.second.fd, &i, sizeof(i)) == sizeof(i));
  assert(i == 42);
  i = 0x12345678;
  assert(write(sp.second.fd, &i, sizeof(i)) == sizeof(i));
  assert(read(sp.first.fd, &i, sizeof(i)) == sizeof(i));
  assert(i == 0x12345678);
}
