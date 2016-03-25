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
    typename OnSuccess
  , typename OnError
  >
  class client_handshake : asio::coroutine {
  public:
    explicit
    client_handshake(
      endpoint_type&& endpoint
    , session_data& session
    , socket_type& socket
    , OnSuccess on_success
    , OnError on_error
    )
      : endpoint_(std::move(endpoint))
      , session_(session)
      , socket_(socket)
      , on_success_(std::move(on_success))
      , on_error_(std::move(on_error))
    {}

    void
    operator()(
      std::error_code ec = std::error_code()
    , std::size_t = 0
    ) {
      if (ec) {
        on_error_(ec);
        return;
      }

      reenter (this) {
        yield socket_.async_connect(endpoint_, std::move(*this));
        make_hello();
        yield send_hello(socket_, std::move(*this));
        yield await_hello_response(socket_, std::move(*this));
        if (process_hello_response()) {
          on_success_();
        } else {
          // TODO custom error_code (this one is defaulted to indicate no error)
          on_error_(ec);
        }
      }
    }

  private:
    void
    make_hello()
    noexcept {
      handshake_hello hello(session_.hello_buffer);
      hello.set_public_key(session_.local_public_key);
      hello.generate_reply_nonce();
      hello.copy_reply_nonce(session_.decrypt_nonce);
      hello.encrypt_to(session_.remote_public_key);
    }

    template <typename Callback>
    void
    send_hello(socket_type& socket, Callback&& callback)
    noexcept {
      asio::async_write(
        socket
      , asio::buffer(session_.hello_buffer)
      , std::forward<Callback>(callback)
      );
    }

    template <typename Callback> void
    await_hello_response(
      socket_type& socket, Callback&& callback
    )
    noexcept {
      asio::async_read(
        socket
      , asio::buffer(session_.hello_response_buffer)
      , std::forward<Callback>(callback)
      );
    }

    bool
    process_hello_response()
    noexcept {
      auto response = handshake_response::decrypt(
        session_.hello_response_buffer
      , session_.decrypt_nonce
      , session_.remote_public_key
      , session_.local_private_key
      );

      if (!response) {
        return false;
      }

      response->copy_reply_nonce(session_.encrypt_nonce);
      response->copy_followup_nonce(session_.decrypt_nonce);

      return true;
    }

    endpoint_type endpoint_;
    session_data& session_;
    socket_type& socket_;
    OnSuccess on_success_;
    OnError on_error_;
  };
}}
