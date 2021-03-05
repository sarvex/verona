// Copyright Microsoft and Project Verona Contributors.
// SPDX-License-Identifier: MIT

#pragma once
namespace sandbox
{
  /**
   * Helper that constructs a deleter from a C function, so that it can
   * be used with `std::unique_ptr`.
   */
  template<auto fn>
  using deleter_from_fn = std::integral_constant<decltype(fn), fn>;

  /**
   * Pointer from `malloc` that will be automatically `free`d.
   */
  template<typename T>
  using unique_c_ptr = std::unique_ptr<T, deleter_from_fn<::free>>;
}
