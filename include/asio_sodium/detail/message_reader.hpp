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

#ifndef ASIO_SODIUM_63f2103d_ba5b_4ebc_8b42_63e8d851cd08
#define ASIO_SODIUM_63f2103d_ba5b_4ebc_8b42_63e8d851cd08

#include "../errors.hpp"

#include "asio_types.hpp"
#include "message_header.hpp"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated"
#include <asio/coroutine.hpp>
#pragma clang diagnostic pop

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-local-typedef"
#include <asio/read.hpp>
#include <asio/write.hpp>
#pragma clang diagnostic pop

#include <asio/yield.hpp>

namespace asio_sodium {
namespace detail {
  template <typename Resumable>
  class message_reader final : asio::coroutine {
  public:
    explicit
    message_reader(
      gsl::span<byte> message_buffer
    , socket_type& socket
    , session_data& session
    , Resumable&& resumable
    )
      : message_buffer_(message_buffer)
      , socket_(socket)
      , session_(session)
      , resumable_(std::move(resumable))
    {}

    void
    operator()(
      std::error_code ec = std::error_code()
    , std::size_t bytes = 0
    ) {
      if (ec) {
        resumable_(ec, bytes);
        return;
      }

      reenter (this) {
        yield read_header();
        ec = process_header();
        if (ec) {
          resumable_(ec, bytes);
          yield break;
        }
        yield read_mac();
        yield read_message();
        ec = decrypt_message();
        if (ec) {
          resumable_(ec, bytes);
          yield break;
        }

        resumable_(std::error_code(), 0);
      }
    }

    void
    read_header()
    noexcept {
      asio::async_read(
        socket_
      , asio::buffer(session_.header_buffer)
      , std::move(*this)
      );
    }

    std::error_code
    process_header() {
      auto const header = message_header::decrypt(
        session_.header_buffer
      , session_.decrypt_nonce
      , session_.remote_public_key
      , session_.local_private_key
      );

      if (!header) {
        return error::message_header_decrypt;
      }

      message_length_ = header->message_length();
      if (message_length_ > message_buffer_.size()) {
        return error::message_too_large;
      }

      return {};
    }

    void
    read_mac()
    noexcept {
      asio::async_read(
        socket_
      , asio::buffer(session_.mac)
      , std::move(*this)
      );
    }

    void
    read_message()
    noexcept {
      asio::async_read(
        socket_
      , asio::buffer(&message_buffer_[0], message_length_)
      , std::move(*this)
      );
    }

    std::error_code
    decrypt_message()
    noexcept {
      auto ciphertext = message_buffer_.first(message_length_);

      message_header const header(
        session_.header_buffer
      );

      header.copy_followup_nonce(session_.decrypt_nonce);

      auto const data_nonce = header.data_nonce_span();
      if (
        crypto_box_open_detached(
          &ciphertext[0]
        , &ciphertext[0]
        , &session_.mac[0]
        , static_cast<std::size_t>(ciphertext.size())
        , &data_nonce[0]
        , &session_.remote_public_key[0]
        , &session_.local_private_key[0]
        )
        != 0
      ) {
        return error::message_decrypt;
      } else {
        return {};
      }
    }

  private:
    gsl::span<byte> message_buffer_;
    socket_type& socket_;
    session_data& session_;
    Resumable resumable_;
    uint32_t message_length_;
  };
}}

#endif
