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

  namespace internal
  {
    /**
     * Template that deduces the return type and argument types for a function
     * `signature<void(int, float)>::return_type` is `void` and
     * `signature<void(int, float)>::argument_type` is `std::tuple<int, float>`.
     */
    template<typename T>
    struct signature;

    /**
     * Specialisation for when the callee is a value.
     */
    template<typename R, typename... Args>
    struct signature<R(Args...)>
    {
      /**
       * The return type of the function whose type is being extracted.
       */
      using return_type = R;

      /**
       * A tuple type containing all of the argument types of the function
       * whose type is being extracted.
       */
      using argument_type = std::tuple<Args...>;
    };

    /**
     * Specification for when the callee is a reference.
     */
    template<typename R, typename... Args>
    struct signature<R (&)(Args...)>
    {
      /**
       * The return type of the function whose type is being extracted.
       */
      using return_type = R;

      /**
       * A tuple type containing all of the argument types of the function
       * whose type is being extracted.
       */
      using argument_type = std::tuple<Args...>;
    };
  }
}
