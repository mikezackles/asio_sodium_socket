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

#ifndef ASIO_SODIUM_8a4c094b_6c1f_40d5_acb8_7b1652a8fde6
#define ASIO_SODIUM_8a4c094b_6c1f_40d5_acb8_7b1652a8fde6

#include "../crypto.hpp"

#include <asio/buffer.hpp>
#include <optional.hpp>

namespace asio_sodium {
namespace detail {
  class handshake_response_view final {
    static constexpr std::size_t
    reply_nonce_offset = crypto_box_MACBYTES;

    static constexpr std::size_t
    followup_nonce_offset =
      reply_nonce_offset + crypto_box_NONCEBYTES
    ;

  public:
    static constexpr std::size_t
    buffer_size =
      followup_nonce_offset + crypto_box_NONCEBYTES
    ;

    static constexpr std::size_t
    data_size =
      buffer_size - crypto_box_MACBYTES
    ;

    constexpr
    handshake_response_view(
      gsl::span<byte, buffer_size> view
    ) noexcept
      : view_(view)
    {}

    constexpr auto
    span() noexcept { return view_; }

    constexpr auto
    data_span() noexcept { return view_.last<data_size>(); }

    auto
    buffer() noexcept { return asio::buffer(&view_[0], view_.size()); }

    constexpr nonce_span
    reply_nonce_field() noexcept {
      return view_.subspan<reply_nonce_offset, crypto_box_NONCEBYTES>();
    }

    constexpr nonce_span const
    reply_nonce_field() const noexcept {
      return const_cast<handshake_response_view&>(*this).reply_nonce_field();
    }

    constexpr nonce_span
    followup_nonce_field() noexcept {
      return view_.last<crypto_box_NONCEBYTES>();
    }

    constexpr nonce_span const
    followup_nonce_field() const noexcept {
      return const_cast<handshake_response_view&>(*this).followup_nonce_field();
    }

  private:
    gsl::span<byte, buffer_size> view_;
  };

  class handshake_response final {
    static constexpr std::size_t
    buffer_size = handshake_response_view::buffer_size;
  public:
    template <typename T>
    using optional = std::experimental::optional<T>;
    using buffer = std::array<byte, buffer_size>;

    explicit handshake_response(
      buffer& data
    ) noexcept
      : view_(gsl::as_span(data))
    {}

    explicit handshake_response(
      handshake_response_view view
    ) noexcept
      : view_(view)
    {}

    static
    optional<handshake_response>
    decrypt(
      buffer& data
    , nonce const& nonce
    , public_key const& remote_key
    , private_key const& private_key
    )
    noexcept {
      handshake_response_view view{gsl::as_span(data)};
      auto full_span = view.span();
      auto data_span = view.data_span();

      if (
        crypto_box_open_easy(
          &data_span[0]
        , &full_span[0]
        , full_span.size()
        , &nonce[0]
        , &remote_key[0]
        , &private_key[0]
        )
        == 0
      ) {
        return handshake_response(view);
      } else {
        return {};
      }
    }

    void generate_reply_nonce() noexcept {
      auto reply_nonce = view_.reply_nonce_field();
      randombytes_buf(&reply_nonce[0], reply_nonce.size());
    }

    void generate_followup_nonce() noexcept {
      auto followup_nonce = view_.followup_nonce_field();
      randombytes_buf(&followup_nonce[0], followup_nonce.size());
    }

    constexpr nonce_span const
    reply_nonce_span() const noexcept {
      return view_.reply_nonce_field();
    }

    void
    copy_reply_nonce(nonce& result) const noexcept {
      auto reply_nonce = view_.reply_nonce_field();
      std::copy(
        reply_nonce.begin()
      , reply_nonce.end()
      , result.begin()
      );
    }

    constexpr nonce_span const
    followup_nonce_span() const noexcept {
      return view_.followup_nonce_field();
    }

    void
    copy_followup_nonce(nonce& result) const noexcept {
      auto followup_nonce = view_.followup_nonce_field();
      std::copy(
        followup_nonce.begin()
      , followup_nonce.end()
      , result.begin()
      );
    }

    bool
    encrypt_to(
      nonce const& nonce
    , public_key const& remote_key
    , private_key const& private_key
    ) noexcept {
      auto full_span = view_.span();
      auto data_span = view_.data_span();

      return
        crypto_box_easy(
          &full_span[0]
        , &data_span[0]
        , data_span.size()
        , &nonce[0]
        , &remote_key[0]
        , &private_key[0]
        )
        == 0
      ;
    }

  private:
    handshake_response_view view_;
  };
}}

#endif
