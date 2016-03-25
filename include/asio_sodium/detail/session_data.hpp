#pragma once

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
    mac mac_;
    handshake_hello::buffer hello_buffer;
    handshake_response::buffer hello_response_buffer;
    message_header::buffer header_buffer;
  };
}}
