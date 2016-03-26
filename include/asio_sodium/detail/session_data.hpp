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

#ifndef ASIO_SODIUM_777dbf21_f3d8_4d87_8a5b_208d2f9259fa
#define ASIO_SODIUM_777dbf21_f3d8_4d87_8a5b_208d2f9259fa

#include "handshake_hello.hpp"
#include "handshake_response.hpp"
#include "message_header.hpp"

namespace asio_sodium {
namespace detail {
  struct session_data {
    explicit
    session_data(
      public_key const& remote_public_key_
    , public_key const& local_public_key_
    , private_key const& local_private_key_
    )
    noexcept
      : remote_public_key(remote_public_key_)
      , local_public_key(local_public_key_)
      , local_private_key(local_private_key_)
    {}

    explicit
    session_data(
      public_key const& local_public_key_
    , private_key const& local_private_key_
    )
    noexcept
      : local_public_key(local_public_key_)
      , local_private_key(local_private_key_)
    {}

    nonce decrypt_nonce;
    nonce encrypt_nonce;
    public_key remote_public_key;
    public_key local_public_key;
    // TODO - RAII wrapper to wipe this on destruct!
    private_key local_private_key;
    mac mac;
    handshake_hello::buffer hello_buffer;
    handshake_response::buffer hello_response_buffer;
    message_header::buffer header_buffer;
  };
}}

#endif
