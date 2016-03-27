/*
 * Copyright 2016 Zachary Michaels
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

#ifndef ASIO_SODIUM_75226a68_a8b1_4eba_839c_08df9c278729
#define ASIO_SODIUM_75226a68_a8b1_4eba_839c_08df9c278729

#include <array>
#include <sodium.h>
#include <span.h>

namespace asio_sodium {
  using byte = unsigned char;
  using public_key = std::array<byte, crypto_box_PUBLICKEYBYTES>;
  using private_key = std::array<byte, crypto_box_SECRETKEYBYTES>;
  using nonce = std::array<byte, crypto_box_NONCEBYTES>;
  using message_authentication_code = std::array<byte, crypto_box_MACBYTES>;
  using public_key_span = gsl::span<byte, crypto_box_PUBLICKEYBYTES>;
  using private_key_span = gsl::span<byte, crypto_box_SECRETKEYBYTES>;
  using nonce_span = gsl::span<byte, crypto_box_NONCEBYTES>;
  using mac_span = gsl::span<byte, crypto_box_MACBYTES>;
}

#endif
