#ifndef ASIO_SODIUM_46c5462e_db6a_4c1d_904f_9b6966425e8a
#define ASIO_SODIUM_46c5462e_db6a_4c1d_904f_9b6966425e8a

#include "../errors.hpp"
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
        yield connect();
        ec = make_hello();
        if (ec) {
          on_error_(ec);
          yield break;
        }
        yield send_hello();
        yield await_hello_response();
        ec = process_hello_response();
        if (ec) {
          on_error_(ec);
          yield break;
        }
        on_success_();
      }
    }

  private:
    void connect() {
      socket_.async_connect(endpoint_, std::move(*this));
    }

    std::error_code
    make_hello()
    noexcept {
      handshake_hello hello(session_.hello_buffer);
      hello.set_public_key(session_.local_public_key);
      hello.generate_reply_nonce();
      hello.copy_reply_nonce(session_.decrypt_nonce);
      if (!hello.encrypt_to(session_.remote_public_key)) {
        return error::handshake_hello_encrypt;
      } else {
        return {};
      }
    }

    void
    send_hello()
    noexcept {
      asio::async_write(
        socket_
      , asio::buffer(session_.hello_buffer)
      , std::move(*this)
      );
    }

    void
    await_hello_response()
    noexcept {
      asio::async_read(
        socket_
      , asio::buffer(session_.hello_response_buffer)
      , std::move(*this)
      );
    }

    std::error_code
    process_hello_response()
    noexcept {
      auto response = handshake_response::decrypt(
        session_.hello_response_buffer
      , session_.decrypt_nonce
      , session_.remote_public_key
      , session_.local_private_key
      );

      if (!response) {
        return error::handshake_response_decrypt;
      }

      response->copy_reply_nonce(session_.encrypt_nonce);
      response->copy_followup_nonce(session_.decrypt_nonce);

      return {};
    }

    endpoint_type endpoint_;
    session_data& session_;
    socket_type& socket_;
    OnSuccess on_success_;
    OnError on_error_;
  };
}}

#endif
