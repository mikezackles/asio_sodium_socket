/*
 * Copyright 2016 Zachary Michaels. All rights reserved.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ASIO_SODIUM_894c8fe0_d50a_435f_8d32_eb2c8123a463
#define ASIO_SODIUM_894c8fe0_d50a_435f_8d32_eb2c8123a463

// The wire format uses a little endian encoding (since that's efficient for
// the common platforms).
#if !defined(ASIO_SODIUM_LITTLEENDIAN)
  #if defined(__GNUC__) || defined(__clang__)
    #ifdef __BIG_ENDIAN__
      #define ASIO_SODIUM_LITTLEENDIAN 0
    #else
      #define ASIO_SODIUM_LITTLEENDIAN 1
    #endif // __BIG_ENDIAN__
  #elif defined(_MSC_VER)
    #if defined(_M_PPC)
      #define ASIO_SODIUM_LITTLEENDIAN 0
    #else
      #define ASIO_SODIUM_LITTLEENDIAN 1
    #endif
  #else
    #error Unable to determine endianness, define ASIO_SODIUM_LITTLEENDIAN.
  #endif
#endif // !defined(ASIO_SODIUM_LITTLEENDIAN)

namespace asio_sodium {
namespace detail {
  template<typename Scalar>
  inline Scalar
  byte_swap_if_big_endian(Scalar scalar) {
    #if ASIO_SODIUM_LITTLEENDIAN
      return scalar;
    #else
      #if defined(_MSC_VER)
        #pragma push_macro("__builtin_bswap16")
        #pragma push_macro("__builtin_bswap32")
        #pragma push_macro("__builtin_bswap64")
        #define __builtin_bswap16 _byteswap_ushort
        #define __builtin_bswap32 _byteswap_ulong
        #define __builtin_bswap64 _byteswap_uint64
      #endif
      // If you're on the few remaining big endian platforms, we make the bold
      // assumption you're also on gcc/clang, and thus have bswap intrinsics:
      if (sizeof(Scalar) == 1) {   // Compile-time if-then's.
        return scalar;
      } else if (sizeof(Scalar) == 2) {
        auto r = __builtin_bswap16(*reinterpret_cast<uint16_t *>(&scalar));
        return *reinterpret_cast<Scalar *>(&r);
      } else if (sizeof(Scalar) == 4) {
        auto r = __builtin_bswap32(*reinterpret_cast<uint32_t *>(&scalar));
        return *reinterpret_cast<Scalar *>(&r);
      } else if (sizeof(Scalar) == 8) {
        auto r = __builtin_bswap64(*reinterpret_cast<uint64_t *>(&scalar));
        return *reinterpret_cast<Scalar *>(&r);
      } else {
        assert(0);
      }
      #if defined(_MSC_VER)
        #pragma pop_macro("__builtin_bswap16")
        #pragma pop_macro("__builtin_bswap32")
        #pragma pop_macro("__builtin_bswap64")
      #endif
    #endif
  }
}}

#endif
