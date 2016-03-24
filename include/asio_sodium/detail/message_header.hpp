#pragma once

#include "../crypto.hpp"
#include "endianness.hpp"

#include <asio/buffer.hpp>
#include <optional.hpp>
#include <span.h>

namespace asio_sodium {
namespace detail {
  class message_header_view {
    using byte = unsigned char;

    static constexpr std::size_t
    data_nonce_offset = crypto_box_MACBYTES;

    static constexpr std::size_t
    followup_nonce_offset =
      data_nonce_offset + crypto_box_NONCEBYTES
    ;

    static constexpr std::size_t
    message_length_offset =
      followup_nonce_offset + crypto_box_NONCEBYTES
    ;

  public:
    static constexpr std::size_t
    buffer_size =
      message_length_offset + sizeof(uint32_t)
    ;

    static constexpr std::size_t
    data_size =
      buffer_size - crypto_box_MACBYTES
    ;

    using length_span = gsl::span<byte, sizeof(uint32_t)>;

    constexpr
    message_header_view(
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
    data_nonce_field() noexcept {
      return view_.subspan<data_nonce_offset, crypto_secretbox_NONCEBYTES>();
    }

    constexpr nonce_span const
    data_nonce_field() const noexcept {
      return const_cast<message_header_view&>(*this).data_nonce_field();
    }

    constexpr nonce_span
    followup_nonce_field() noexcept {
      return span().subspan<followup_nonce_offset, crypto_box_NONCEBYTES>();
    }

    constexpr nonce_span const
    followup_nonce_field() const noexcept {
      return const_cast<message_header_view&>(*this).followup_nonce_field();
    }

    constexpr length_span
    message_length_field() noexcept {
      return span().subspan<message_length_offset, sizeof(uint32_t)>();
    }

    constexpr length_span const
    message_length_field() const noexcept {
      return const_cast<message_header_view&>(*this).message_length_field();
    }

  private:
    gsl::span<byte, buffer_size> view_;
  };

  class message_header final {
    static constexpr std::size_t
    buffer_size = message_header_view::buffer_size;
  public:
    template <typename T>
    using optional = std::experimental::optional<T>;
    using buffer = std::array<byte, buffer_size>;

    explicit message_header(
      buffer& data
    ) noexcept
      : view_(gsl::as_span(data))
    {}

    explicit message_header(
      message_header_view view
    ) noexcept
      : view_(view)
    {}

    static
    optional<message_header>
    decrypt(
      buffer& data
    , nonce const& nonce
    , public_key const& public_key
    , private_key const& private_key
    )
    noexcept {
      message_header_view view{gsl::as_span(data)};
      auto full_span = view.span();
      auto data_span = view.data_span();

      if (
        crypto_box_open_easy(
          &data_span[0]
        , &full_span[0]
        , full_span.size()
        , &nonce[0]
        , &public_key[0]
        , &private_key[0]
        )
        == 0
      ) {
        return message_header(view);
      } else {
        return {};
      }
    }

    void
    generate_data_nonce() noexcept {
      auto data_nonce = view_.data_nonce_field();
      randombytes_buf(&data_nonce[0], data_nonce.size());
    }

    void
    generate_followup_nonce() noexcept {
      auto followup_nonce = view_.followup_nonce_field();
      randombytes_buf(&followup_nonce[0], followup_nonce.size());
    }

    void
    set_message_length(uint32_t length) noexcept {
      using length_span = message_header_view::length_span;
      length = byte_swap_if_big_endian(length);
      length_span source{reinterpret_cast<byte*>(&length), sizeof(uint32_t)};
      length_span target = view_.message_length_field();
      std::copy(
        source.begin()
      , source.end()
      , target.begin()
      );
    }

    constexpr nonce_span const
    data_nonce_span() const noexcept {
      return view_.data_nonce_field();
    }

    void
    copy_data_nonce(nonce& result) const {
      auto data_nonce = view_.data_nonce_field();
      std::copy(
        data_nonce.begin()
      , data_nonce.end()
      , result.begin()
      );
    }

    constexpr nonce_span const
    followup_nonce_span() const noexcept {
      return view_.followup_nonce_field();
    }

    void
    copy_followup_nonce(nonce& result) const {
      auto followup_nonce = view_.followup_nonce_field();
      std::copy(
        followup_nonce.begin()
      , followup_nonce.end()
      , result.begin()
      );
    }

    uint32_t
    message_length() const noexcept {
      using length_span = message_header_view::length_span;
      uint32_t result;
      length_span source = view_.message_length_field();
      length_span target{reinterpret_cast<byte*>(&result), sizeof(uint32_t)};
      std::copy(
        source.begin()
      , source.end()
      , target.begin()
      );
      result = byte_swap_if_big_endian(result);
      return result;
    }

    bool
    encrypt_to(
      nonce const& nonce
    , public_key const& public_key
    , private_key const& private_key
    )
    noexcept {
      auto full_span = view_.span();
      auto data_span = view_.data_span();

      return
        crypto_box_easy(
          &full_span[0]
        , &data_span[0]
        , data_span.size()
        , &nonce[0]
        , &public_key[0]
        , &private_key[0]
        )
        == 0
      ;
    }

  private:
    message_header_view view_;
  };
}}
