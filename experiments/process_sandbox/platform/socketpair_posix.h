// Copyright Microsoft and Project Verona Contributors.
// SPDX-License-Identifier: MIT
#pragma once
#ifdef __unix__
#  include <sys/socket.h>
#  include <sys/types.h>

namespace sandbox
{
  namespace platform
  {
    class SocketPairPosix
    {
    public:
      static std::pair<Handle, Handle> create()
      {
        int socks[2];
        if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, socks))
        {
          err(1, "Failed to create socket pair");
        }
        return {socks[0], socks[1]};
      }
    };
  }
}
#endif
