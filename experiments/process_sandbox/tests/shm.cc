// Copyright Microsoft and Project Verona Contributors.
// SPDX-License-Identifier: MIT
#include <platform/platform.h>

using namespace sandbox::platform;

template<typename Map>
void test_map()
{
  // Pick a fairly small size so we won't exhaust memory on a CI VM.
  size_t log2size = 20;
  size_t size = 1 << log2size;
  uintptr_t address_mask = size - 1;
  // Construct the shared memory object.
  Map m(log2size);
  // Is the base correctly aligned?
  uintptr_t base = reinterpret_cast<uintptr_t>(m.get_base());
  assert((base & address_mask) == 0);
  // Is the size what we asked for?
  assert(m.get_size() == size);
  // Can we at least write to and read from the first and last byte?
  auto cp = static_cast<volatile char*>(m.get_base());
  cp[0] = 12;
  cp[size - 1] = 42;
  assert(cp[0] == 12);
  assert(cp[size - 1] == 42);
}

using FallbackMap =
#ifdef __unix__
  SharedMemoryMapPOSIX<detail::SharedMemoryObjectPOSIX>
#else
  SharedMemoryMap
#endif
  ;

int main(void)
{
  test_map<SharedMemoryMap>();
  // If we are using a specialised version, also test the portable version
  if constexpr (!std::is_same_v<FallbackMap, SharedMemoryMap>)
  {
    test_map<FallbackMap>();
  }
}
