// Copyright Microsoft and Project Verona Contributors.
// SPDX-License-Identifier: MIT

#include "child_malloc.h"
#include "host_service_calls.h"
#include "platform/platform.h"
#include "privilege_elevation_upcalls.h"
#include "sandbox.hh"
#include "shared.h"
#include "shared_memory_region.h"

#include <assert.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <ucontext.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#  ifdef MAP_EXCL
#    define MAP_FIXED_NOREPLACE MAP_FIXED | MAP_EXCL
#  else
#    define MAP_FIXED_NOREPLACE MAP_FIXED
#  endif
#endif

using address_t = snmalloc::Aal::address_t;

// A few small platform-specific tweaks that aren't yet worth adding to the
// platform abstraction layer.
#ifdef __FreeBSD__
// On FreeBSD, libc interposes on some system calls and does so in a way that
// causes them to segfault if they are invoked before libc is fully
// initialised.  We must instead call the raw system call versions.
extern "C" ssize_t __sys_write(int fd, const void* buf, size_t nbytes);
extern "C" ssize_t __sys_read(int fd, void* buf, size_t nbytes);
#  define write __sys_write
#  define read __sys_read
#elif defined(__linux__)
namespace
{
  /**
   * Linux run-time linkers do not currently support fdlopen, but it can be
   * emulated with a wrapper that relies on procfs.  Each fd open in a
   * process exists as a file (typically a symlink) in /proc/{pid}/fd/{fd
   * number}, so we can open that.  This does depend on the running process
   * having access to its own procfs entries, which may be a problem for some
   * possible sandboxing approaches.
   */
  void* fdlopen(int fd, int flags)
  {
    char* str;
    asprintf(&str, "/proc/%d/fd/%d", (int)getpid(), fd);
    void* ret = dlopen(str, flags);
    free(str);
    return ret;
  }
  typedef void (*dlfunc_t)(void);

  /**
   * It is undefined behaviour in C to cast from a `void*` to a function
   * pointer, but POSIX only provides a single function to get a pointer from a
   * library.  BSD systems provide `dlfunc` to avoid this but glibc does not,
   * so we provide our own.
   */
  dlfunc_t dlfunc(void* handle, const char* symbol)
  {
    return (dlfunc_t)dlsym(handle, symbol);
  }
}
#endif

extern "C"
{
  /**
   * The `environ` symbol is exported by libc, but not exposed in any header.
   *  We need to access this directly during bootstrap, when the libc functions
   *  that access it may not yet be ready.
   */
  extern char** environ;
}

sandbox::ProxyPageMap sandbox::ProxyPageMap::p;

using namespace snmalloc;
using namespace sandbox;

namespace
{
  /**
   * Flag indicating that bootstrapping has finished.  Note that we cannot
   * create any threads until after malloc is set up and so this does not need
   * to be atomic: It is never modified after the second thread is created.
   */
  bool done_bootstrapping = false;

  /**
   * Bootstrap function.  Map the shared memory region and configure everything
   * needed for malloc.
   */
  SNMALLOC_SLOW_PATH
  void bootstrap();

  /**
   * The start of the shared memory region.  Passed as a command-line argument.
   */
  void* shared_memory_start = 0;

  /**
   * The end of the shared memory region.  Passed as a command-line argument.
   */
  void* shared_memory_end = 0;

  /**
   * Pointer to the shared memory region.  This will be equal to
   * `shared_memory_start` and is simply a convenience to have a pointer of the
   * correct type.
   */
  SharedMemoryRegion* shared = nullptr;

  /**
   * Synchronous RPC call to the parent environment.  This sends a message to
   * the parent and waits for a response.  These calls should never return an
   * error and so this aborts the process if they do.
   *
   * This function is called during early bootstrapping and so cannot use any
   * libc features that either depend on library initialisation or which
   * allocate memory.
   */
  uintptr_t
  requestHostService(HostServiceCallID id, uintptr_t arg0, uintptr_t arg1 = 0)
  {
    static std::atomic_flag lock;
    FlagLock g(lock);
    HostServiceRequest req{id, arg0, arg1};
    auto written_bytes = write(PageMapUpdates, &req, sizeof(req));
    assert(written_bytes == sizeof(req));
    HostServiceResponse response;
    auto read_bytes = read(PageMapUpdates, &response, sizeof(response));
    assert(read_bytes == sizeof(response));

    if (response.error)
    {
      DefaultPal::error("Host returned an error.");
    }
    return response.ret;
  }
}

MemoryProviderProxy* MemoryProviderProxy::make() noexcept
{
  if (unlikely(!done_bootstrapping))
  {
    bootstrap();
  }
  static MemoryProviderProxy singleton;
  return &singleton;
}

namespace sandbox
{
  void ProxyPageMap::set(uintptr_t p, uint8_t x)
  {
    assert(
      (p >= reinterpret_cast<uintptr_t>(shared_memory_start)) &&
      (p < reinterpret_cast<uintptr_t>(shared_memory_end)));
    requestHostService(
      ChunkMapSet, reinterpret_cast<uintptr_t>(p), static_cast<uintptr_t>(x));
  }

  uint8_t ProxyPageMap::get(address_t p)
  {
    return GlobalPagemap::pagemap().get(p);
  }

  uint8_t ProxyPageMap::get(void* p)
  {
    return GlobalPagemap::pagemap().get(address_cast(p));
  }

  void ProxyPageMap::set_slab(snmalloc::Superslab* slab)
  {
    set(reinterpret_cast<uintptr_t>(slab), (size_t)CMSuperslab);
  }

  void ProxyPageMap::clear_slab(snmalloc::Superslab* slab)
  {
    set(reinterpret_cast<uintptr_t>(slab), (size_t)CMNotOurs);
  }

  void ProxyPageMap::clear_slab(snmalloc::Mediumslab* slab)
  {
    set(reinterpret_cast<uintptr_t>(slab), (size_t)CMNotOurs);
  }

  void ProxyPageMap::set_slab(snmalloc::Mediumslab* slab)
  {
    set(reinterpret_cast<uintptr_t>(slab), (size_t)CMMediumslab);
  }

  void ProxyPageMap::set_large_size(void* p, size_t size)
  {
    size_t size_bits = bits::next_pow2_bits(size);
    assert((p >= shared_memory_start) && (p < shared_memory_end));
    requestHostService(
      ChunkMapSetRange,
      reinterpret_cast<uintptr_t>(p),
      static_cast<uintptr_t>(size_bits));
  }

  void ProxyPageMap::clear_large_size(void* p, size_t size)
  {
    assert((p >= shared_memory_start) && (p < shared_memory_end));
    size_t size_bits = bits::next_pow2_bits(size);
    requestHostService(
      ChunkMapClearRange,
      reinterpret_cast<uintptr_t>(p),
      static_cast<uintptr_t>(size_bits));
  }

  void* MemoryProviderProxy::pop_large_stack(size_t large_class)
  {
    return reinterpret_cast<void*>(requestHostService(
      MemoryProviderPopLargeStack, static_cast<uintptr_t>(large_class)));
  }

  void
  MemoryProviderProxy::push_large_stack(Largeslab* slab, size_t large_class)
  {
    requestHostService(
      MemoryProviderPushLargeStack,
      reinterpret_cast<uintptr_t>(slab),
      static_cast<uintptr_t>(large_class));
  }

  void* MemoryProviderProxy::reserve_committed_size(size_t size) noexcept
  {
    size_t size_bits = snmalloc::bits::next_pow2_bits(size);
    size_t large_class = std::max(size_bits, SUPERSLAB_BITS) - SUPERSLAB_BITS;
    return reserve_committed(large_class);
  }
  void* MemoryProviderProxy::reserve_committed(size_t large_class) noexcept
  {
    return reinterpret_cast<void*>(requestHostService(
      MemoryProviderReserve, static_cast<uintptr_t>(large_class)));
  }

}

namespace
{
  /**
   * The function from the loaded library that provides the vtable dispatch
   * for functions that we invoke.
   */
  void (*sandbox_invoke)(int, void*);

  /**
   * The run loop.  Takes the public interface of this library (effectively,
   * the library's vtable) as an argument.  Exits when the upcall depth changes
   * when waiting
   */
  void runloop(int upcall_depth = 0)
  {
	  int new_depth;
    do
    {
      while (!shared->token.child.wait(INT_MAX))
      {}
      if (shared->should_exit)
      {
        exit(0);
      }
      assert(shared->token.is_child_executing);
      int idx = shared->function_index;
      void* buf = shared->msg_buffer;
      shared->msg_buffer = nullptr;
      try
      {
        if ((buf != nullptr) && (sandbox_invoke != nullptr))
          sandbox_invoke(idx, buf);
      }
      catch (...)
      {
        // FIXME: Report error in some useful way.
        printf("Exception!\n");
      }
	  new_depth = shared->token.upcall_depth;
      shared->token.is_child_executing = false;
      shared->token.parent.wake();
    } while (new_depth == upcall_depth);
  }

  SNMALLOC_SLOW_PATH
  void bootstrap()
  {
    void* addr = nullptr;
    size_t length = 0;
    // Find the correct environment variables.  Note that libc is not fully
    // initialised when this is called and so we have to be very careful about
    // the libc function that we call.  We use the `environ` variable directly,
    // rather than `getenv`, which may allocate memory.
    //
    // The parent process provides the shared memory object in the file
    // descriptor with the number given by `SharedMemRegion` and the location
    // where it should be mapped in an environment variable.  The child has to
    // map this as the first step in bootstrapping (before most of libc
    // initialises itself) to get a working heap.
    for (char** e = environ; *e != nullptr; e++)
    {
      char* ev = *e;
      const char ev_name[] = "SANDBOX_LOCATION=";
      const size_t name_length = sizeof(ev_name) - 1;
      if (strncmp(ev_name, ev, name_length) == 0)
      {
        ev += name_length;
        char* end;
        addr = reinterpret_cast<void*>(strtoull(ev, &end, 16));
        assert(end[0] == ':');
        length = strtoull(end + 1, nullptr, 16);
        break;
      }
    }
    // Abort if we weren't able to find the correct lengths.
    if ((addr == nullptr) || (length == 0))
    {
      DefaultPal::error("Unable to find memory location");
    }

    // fprintf(stderr, "Child starting\n");
    // printf(
    //"Child trying to map fd %d at addr %p (0x%zx)\n", SharedMemRegion, addr,
    // length);
    void* ptr = mmap(
      addr,
      length,
      PROT_READ | PROT_WRITE,
      MAP_FIXED_NOREPLACE | MAP_SHARED | platform::detail::map_nocore,
      SharedMemRegion,
      0);

    // printf("%p\n", ptr);
    if (ptr == MAP_FAILED)
    {
      err(1, "Mapping shared heap failed");
    }

    shared = reinterpret_cast<SharedMemoryRegion*>(ptr);
    // Splice the pagemap page inherited from the parent into the pagemap.
    void* pagemap_chunk = GlobalPagemap::pagemap().page_for_address(
      reinterpret_cast<uintptr_t>(ptr));
    munmap(pagemap_chunk, 4096);
    void* shared_pagemap = mmap(
      pagemap_chunk, 4096, PROT_READ, MAP_SHARED | MAP_FIXED, PageMapPage, 0);
    if (shared_pagemap == MAP_FAILED)
    {
      err(1, "Mapping shared pagemap page failed");
    }
    shared_memory_start = shared->start;
    shared_memory_end = shared->end;
    assert(shared_pagemap == pagemap_chunk);
    (void)shared_pagemap;

    done_bootstrapping = true;
  }

  using sandbox::platform::Handle;
  using Socket = sandbox::platform::SocketPair::Socket;
  /**
   * The socket that is used for upcalls to the parent process.
   */
  Socket upcallSocket;

  /**
   * Perform an upcall.  This takes the kind of upcall, the data to be sent,
   * and the file descriptor to send as arguments.  The file descriptor may be
   * -1, in which case the it is not sent.
   *
   *  The return value is the integer result of the upcall and a `Handle` that
   *  is either invalid or the returned file descriptor.
   *
   *  This function should not be called directly, it should be invoked via the
   *  wrapper.
   */
  std::pair<uintptr_t, Handle>
  upcall(sandbox::UpcallKind k, void* buffer, size_t size, int fd)
  {
    Handle out_fd(fd);
    UpcallRequest req{k, size, reinterpret_cast<uintptr_t>(buffer)};
    upcallSocket.send(&req, sizeof(req), out_fd);
    out_fd.take();
    int depth = ++shared->token.upcall_depth;
    (void)depth;
    shared->token.parent.wake();
    while (!shared->token.child.wait(INT_MAX))
    {}
    // runloop(depth);
    Handle in_fd;
    UpcallResponse response;
    upcallSocket.receive(&response, sizeof(response), in_fd);
    return {response.response, std::move(in_fd)};
  }

  /**
   * Perform an upcall, of the specified kind, passing `data`.  The `data`
   * argument must point to the shared heap.
   *
   * If the optional `fd` parameter is passed, then this file descriptor
   * accompanies the upcall.  This is used for calls such as `openat`.
   */
  template<typename T>
  std::pair<uintptr_t, Handle>
  upcall(sandbox::UpcallKind k, T* data, int fd = -1)
  {
    return upcall(k, data, sizeof(T), fd);
  }

int upcall_stat(const char* pathname, struct stat* statbuf)
{
  auto args = std::make_unique<sandbox::UpcallArgs::Stat>();
  unique_c_ptr<char> copy;
  if ((pathname < shared_memory_start) || (pathname >= shared_memory_end))
  {
    copy.reset(strdup(pathname));
    pathname = copy.get();
  }
  args->path = reinterpret_cast<uintptr_t>(pathname);
  args->statbuf = reinterpret_cast<uintptr_t>(statbuf);
  auto ret = upcall(sandbox::UpcallKind::Stat, args.get());
  return static_cast<int>(ret.first);
}

int upcall_openat(int dirfd, const char* pathname, int flags, mode_t mode)
{
  (void)dirfd;
  char buf[128];
  pid_t pid = getpid();
  sprintf(buf, "/proc/%d/fd/%%d", (int)pid);
  int fd = -1;
  if (sscanf(pathname, buf, &fd) == 1)
  {
    return dup(fd);
  }
  if (pathname == nullptr)
  {
    return -EINVAL;
  }
  if (pathname[0] == '/')
  {
    auto args = std::make_unique<sandbox::UpcallArgs::Open>();
    unique_c_ptr<char> copy;
    if ((pathname < shared_memory_start) || (pathname >= shared_memory_end))
    {
      copy.reset(strdup(pathname));
      pathname = copy.get();
    }
    args->path = reinterpret_cast<uintptr_t>(pathname);
    args->flags = flags;
    args->mode = mode;
    auto ret = upcall(sandbox::UpcallKind::Open, args.get());
    int result = static_cast<int>(ret.first);
    if (ret.second.is_valid())
    {
      result = ret.second.take();
    }
    return result;
  }
  return -EINVAL;
}

}

#ifndef USE_CAPSICUM
extern "C" int openat(int dirfd, const char* pathname, int flags, ...)
{
  va_list ap;
  va_start(ap, flags);
  mode_t mode = va_arg(ap, mode_t);
  va_end(ap);
  int ret = upcall_openat(dirfd, pathname, flags, mode);
  if (ret < 0)
  {
    errno = -ret;
    return -1;
  }
  return ret;
}
#endif

void emulate(int signo, siginfo_t* info, ucontext_t* ctx)
{
#ifdef __linux__
  long long arg0 = ctx->uc_mcontext.gregs[REG_RDI];
  long long arg1 = ctx->uc_mcontext.gregs[REG_RSI];
  long long arg2 = ctx->uc_mcontext.gregs[REG_RDX];
  long long arg3 = ctx->uc_mcontext.gregs[REG_R10];
  if (info->si_syscall == 4)
  {
    ctx->uc_mcontext.gregs[REG_RAX] =
      (greg_t)upcall_stat((const char*)arg0, (struct stat*)arg1);
    // Advance the instruction pointer after the syscall instruction
    ctx->uc_mcontext.gregs[REG_RIP] = (greg_t)info->si_call_addr;
  }
  else if (info->si_syscall == 257)
  {
    ctx->uc_mcontext.gregs[REG_RAX] =
      (greg_t)upcall_openat((int)arg0, (const char*)arg1, (int)arg2, (mode_t)arg3);
    // Advance the instruction pointer after the syscall instruction
    ctx->uc_mcontext.gregs[REG_RIP] = (greg_t)info->si_call_addr;
  }
  else
  {
    fprintf(
      stderr,
      "Signal: %d\nFaulting instruction: %p\nSyscall: %d, %p\n",
      signo,
      info->si_call_addr,
      (int)info->si_syscall,
      ctx);
  }
#endif
}

int main()
{
  sandbox::platform::Sandbox::apply_sandboxing_policy_postexec();
#ifdef __linux__
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = (void (*)(int, siginfo_t*, void*))emulate;
  sigaction(SIGSYS, &sa, nullptr);
#endif
  // Close the shared memory region file descriptor before we call untrusted
  // code.
  close(SharedMemRegion);
  close(PageMapPage);
  upcallSocket.reset(FDSocket);

#ifndef NDEBUG
  // Check that our bootstrapping actually did the right thing and that
  // allocated objects are in the shared region.
  auto check_is_in_shared_range = [](void* ptr) {
    assert((ptr >= shared_memory_start) && (ptr < shared_memory_end));
  };
  check_is_in_shared_range(current_alloc_pool());
  check_is_in_shared_range(ThreadAlloc::get_reference());
  void* obj = malloc(42);
  check_is_in_shared_range(obj);
  free(obj);
  fprintf(stderr, "Sandbox: %p--%p\n", shared_memory_start, shared_memory_end);
#endif

  // Load the library using the file descriptor that the parent opened.  This
  // allows a Capsicum sandbox to prevent any access to the global namespace.
  // It is hopefully possible to implement something similar with seccomp-bpf,
  // though this may require calling into the parent to request additional file
  // descriptors and proxying all open / openat calls.
  void* handle = fdlopen(MainLibrary, RTLD_GLOBAL | RTLD_LAZY);
  if (handle == nullptr)
  {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 1;
  }

  // Find the library initialisation function.  This function will generate the
  // vtable.
  auto sandbox_init =
    reinterpret_cast<void (*)()>(dlfunc(handle, "sandbox_init"));
  if (sandbox_init == nullptr)
  {
    fprintf(stderr, "dlfunc failed: %s\n", dlerror());
    return 1;
  }
  // Set up the sandbox
  sandbox_init();
  sandbox_invoke =
    reinterpret_cast<decltype(sandbox_invoke)>(dlfunc(handle, "sandbox_call"));
  assert(sandbox_invoke && "Sandbox invoke invoke function not found");

  shared->token.is_child_executing = false;
  shared->token.is_child_loaded = true;

  // Enter the run loop, waiting for calls from trusted code.
  runloop();

  return 0;
}
