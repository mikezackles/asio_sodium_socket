#pragma once

#include "asio_types.hpp"
#include "handshake_hello.hpp"
#include "handshake_response.hpp"
#include "session_data.hpp"

#include <asio/coroutine.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>
#include <asio/yield.hpp>

namespace asio_sodium {
namespace detail {
  template <
    typename Authenticator
  , typename OnSuccess
  , typename OnError
  >
  class server_handshake : asio::coroutine {
  public:
    explicit
    server_handshake(
      session_data& session
    , socket_type& socket
    , Authenticator authenticator
    , OnSuccess on_success
    , OnError on_error
    )
      : session_(session)
      , socket_(socket)
      , authenticator_(std::move(authenticator))
      , on_success_(std::move(on_success))
      , on_error_(std::move(on_error))
    {}

    void
    operator()(
      std::error_code ec = std::error_code()
    , std::size_t bytes = 0
    ) {
      if (ec) {
        on_error_(ec, bytes);
        return;
      }

      reenter (this) {
        yield await_hello(socket_, std::move(*this));
        // TODO custom error_codes
        if (!process_hello(authenticator_)) {
          on_error_(ec, bytes);
          yield break;
        }
        if (!make_hello_response()) {
          on_error_(ec, bytes);
          yield break;
        }
        yield send_hello_response(
          socket_
        , std::move(*this)
        );
        on_success_();
      }
    }

  private:
    template <typename Callback>
    void
    await_hello(socket_type& socket, Callback&& callback)
    noexcept {
      asio::async_read(
        socket
      , asio::buffer(session_.hello_buffer)
      , std::forward<Callback>(callback)
      );
    }

    template <typename Auth>
    bool
    process_hello(Auth&& auth)
    noexcept {
      auto hello =
        handshake_hello::decrypt(
          session_.hello_buffer
        , session_.local_public_key
        , session_.local_private_key
        )
      ;
      if (!hello) {
        return false;
      }
      auto public_key = hello->public_key_span();
      // Look up the public key and make sure it's authorized
      if (!auth(public_key)) {
        return false;
      }
      std::copy(
        public_key.begin()
      , public_key.end()
      , session_.remote_public_key.begin()
      );
      hello->copy_reply_nonce(session_.encrypt_nonce);
      return true;
    }

    bool
    make_hello_response()
    noexcept {
      handshake_response response{session_.hello_response_buffer};

      response.generate_reply_nonce();
      response.copy_reply_nonce(session_.decrypt_nonce);

      nonce temp_followup_nonce;

      response.generate_followup_nonce();
      response.copy_followup_nonce(temp_followup_nonce);

      if (
        !response.encrypt_to(
          session_.encrypt_nonce
        , session_.remote_public_key
        , session_.local_private_key
        )
      ) {
        return false;
      }

      std::copy(
        temp_followup_nonce.begin()
      , temp_followup_nonce.end()
      , session_.encrypt_nonce.begin()
      );

      return true;
    }

    template <typename Callback> void
    send_hello_response(
      socket_type& socket, Callback&& callback
    )
    noexcept {
      asio::async_write(
        socket
      , asio::buffer(session_.hello_response_buffer)
      , std::forward<Callback>(callback)
      );
    }

    session_data& session_;
    socket_type& socket_;
    Authenticator authenticator_;
    OnSuccess on_success_;
    OnError on_error_;
  };
}}
