#pragma once

#include "asio_types.hpp"

#include <asio/coroutine.hpp>
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
        yield session_.await_hello(socket_, std::move(*this));
        // TODO custom error_codes
        if (!session_.process_hello(authenticator_)) {
          on_error_(ec, bytes);
          yield break;
        }
        if (!session_.make_hello_response()) {
          on_error_(ec, bytes);
          yield break;
        }
        yield session_.send_hello_response(
          socket_
        , std::move(*this)
        );
        on_success_();
      }
    }

  private:
    session_data& session_;
    socket_type& socket_;
    Authenticator authenticator_;
    OnSuccess on_success_;
    OnError on_error_;
  };
}}
