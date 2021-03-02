// Copyright Microsoft and Project Verona Contributors.
// SPDX-License-Identifier: MIT
#include <platform/platform.h>

using namespace sandbox::platform;

int main(void)
{
  auto sp = SocketPair::create();
  auto sp2 = SocketPair::create();
  int i = 42;
  // Check sending succeeds
  assert(sp.first.send(&i, sizeof(i)));
  i = 12;
  // Check receiving succeeds and gives us the value we wanted
  assert(sp.second.receive(&i, sizeof(i)));
  assert(i == 42);
  assert(sp.first.send(&i, sizeof(i)));
  i = 12;
  // Check that we can do the receive that might receive a handle even if no
  // handle was sent and still receive the data portion correctly.
  Handle h;
  assert(sp.second.receive(&i, sizeof(i), h));
  // We didn't receive a handle, so ensure that it doesn't look like we did.
  assert(!h.is_valid());
  // But we did get the data.
  assert(i == 42);
  i = 0x12345678;
  // Send the receive 
  h = std::move(sp2.second);
  assert(sp.first.send(&i, sizeof(i), h));
  assert(sp.second.receive(&i, sizeof(i), h));
  assert(h.is_valid());
  // Check that the received socket is really the same one that we sent by
  // sending something to it and checking that we can receive.
  assert(sp2.first.send(&i, sizeof(i)));
  i = 12;
  SocketPair::Socket newsock;
  newsock.reset(h.take());
  assert(newsock.receive(&i, sizeof(i)));
  assert(i == 0x12345678);
}
