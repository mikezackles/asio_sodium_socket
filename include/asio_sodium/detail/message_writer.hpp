#ifndef ASIO_SODIUM_9c88c531_a60b_4d94_8a00_6205a1e29c10
#define ASIO_SODIUM_9c88c531_a60b_4d94_8a00_6205a1e29c10

#include "../errors.hpp"

#include "asio_types.hpp"
#include "message_header.hpp"

#include <asio/coroutine.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>
#include <asio/yield.hpp>

namespace asio_sodium {
namespace detail {
  template <typename Resumable>
  class message_writer final : asio::coroutine {
  public:
    explicit
    message_writer(
      gsl::span<byte> message
    , socket_type& socket
    , session_data& session
    , Resumable&& resumable
    )
      : message_(message)
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
        ec = encrypt_message_in_place_and_write_header();
        if (ec) {
          resumable_(ec, bytes);
          yield break;
        }
        yield send_header();
        yield send_mac();
        yield send_message_and_invoke_callback();
      }
    }

  private:
    std::error_code
    encrypt_message_in_place_and_write_header()
    noexcept {
      message_header header(session_.header_buffer);
      header.generate_data_nonce();
      header.generate_followup_nonce();
      header.set_message_length(message_.length());

      auto data_nonce = header.data_nonce_span();
      if (
        crypto_box_detached(
          &message_[0]
        , &session_.mac[0]
        , &message_[0]
        , message_.size()
        , &data_nonce[0]
        , &session_.remote_public_key[0]
        , &session_.local_private_key[0]
        ) != 0
      ) {
        return error::message_encrypt;
      }

      nonce temp_followup_nonce;
      header.copy_followup_nonce(temp_followup_nonce);

      if (
        !header.encrypt_to(
          session_.encrypt_nonce
        , session_.remote_public_key
        , session_.local_private_key
        )
      ) {
        return error::message_header_encrypt;
      }

      std::copy(
        temp_followup_nonce.begin()
      , temp_followup_nonce.end()
      , session_.encrypt_nonce.begin()
      );

      return {};
    }

    void
    send_header()
    noexcept {
      asio::async_write(
        socket_
      , asio::buffer(session_.header_buffer)
      , std::move(*this)
      );
    }

    void
    send_mac()
    noexcept {
      asio::async_write(
        socket_
      , asio::buffer(session_.mac)
      , std::move(*this)
      );
    }

    void
    send_message_and_invoke_callback()
    noexcept {
      asio::async_write(
        socket_
      , asio::buffer(&message_[0], message_.size())
      , std::move(resumable_)
      );
    }

    gsl::span<byte> message_;
    socket_type& socket_;
    session_data& session_;
    Resumable resumable_;
  };
}}

#endif
