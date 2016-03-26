#ifndef ASIO_SODIUM_b35b8531_0ae6_45f1_85c9_71c60a0cb3df
#define ASIO_SODIUM_b35b8531_0ae6_45f1_85c9_71c60a0cb3df

#include "../crypto.hpp"

#include <asio/buffer.hpp>
#include <optional.hpp>
#include <sodium.h>
#include <span.h>

namespace asio_sodium {
namespace detail {
  class handshake_hello_view final {
    static constexpr std::size_t
    public_key_offset = crypto_box_SEALBYTES;

    static constexpr std::size_t
    reply_nonce_offset =
      public_key_offset + crypto_box_PUBLICKEYBYTES
    ;

  public:
    static constexpr std::size_t
    buffer_size =
      reply_nonce_offset + crypto_box_NONCEBYTES
    ;

    static constexpr std::size_t
    data_size =
      buffer_size - crypto_box_SEALBYTES
    ;

    constexpr explicit handshake_hello_view(
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

    constexpr public_key_span
    public_key_field() noexcept {
      return view_.subspan<public_key_offset, crypto_box_PUBLICKEYBYTES>();
    }

    constexpr public_key_span const
    public_key_field() const noexcept {
      return const_cast<handshake_hello_view&>(*this).public_key_field();
    }

    constexpr nonce_span
    reply_nonce_field() noexcept {
      return view_.subspan<reply_nonce_offset, crypto_box_NONCEBYTES>();
    }

    constexpr nonce_span const
    reply_nonce_field() const noexcept {
      return const_cast<handshake_hello_view&>(*this).reply_nonce_field();
    }

  private:
    gsl::span<byte, buffer_size> view_;
  };

  class handshake_hello final {
    static constexpr std::size_t
    buffer_size = handshake_hello_view::buffer_size;
  public:
    template <typename T>
    using optional = std::experimental::optional<T>;
    using buffer = std::array<byte, buffer_size>;

    explicit handshake_hello(
      buffer& data
    ) noexcept
      : view_(gsl::as_span(data))
    {}

    explicit handshake_hello(
      handshake_hello_view view
    ) noexcept
      : view_(view)
    {}

    static
    optional<handshake_hello>
    decrypt(
      buffer& data
    , public_key const& receiver_public_key
    , private_key const& receiver_private_key
    )
    noexcept {
      handshake_hello_view view{gsl::as_span(data)};
      auto full_span = view.span();
      auto data_span = view.data_span();

      if (
        crypto_box_seal_open(
          &data_span[0]
        , &full_span[0]
        , full_span.size()
        , &receiver_public_key[0]
        , &receiver_private_key[0]
        )
        == 0
      ) {
        return handshake_hello(view);
      } else {
        return {};
      }
    }

    void
    set_public_key(public_key const& local_key) noexcept {
      std::copy(
        local_key.begin()
      , local_key.end()
      , view_.public_key_field().begin()
      );
    }

    void
    generate_reply_nonce() noexcept {
      auto reply_nonce = view_.reply_nonce_field();
      randombytes_buf(&reply_nonce[0], reply_nonce.size());
    }

    constexpr public_key_span const
    public_key_span() const noexcept {
      return view_.public_key_field();
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

    bool
    encrypt_to(public_key const& remote_key) noexcept {
      auto full_span = view_.span();
      auto data_span = view_.data_span();

      return
        crypto_box_seal(
          &full_span[0]
        , &data_span[0]
        , data_span.size()
        , &remote_key[0]
        )
        == 0
      ;
    }

  private:
    handshake_hello_view view_;
  };
}}

#endif
