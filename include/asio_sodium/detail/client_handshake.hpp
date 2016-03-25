#pragma once

#include "asio_types.hpp"
#include "session_data.hpp"

#include <asio/coroutine.hpp>
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
        session_.make_hello();
        yield session_.send_hello(socket_, std::move(*this));
        yield session_.await_hello_response(socket_, std::move(*this));
        if (session_.process_hello_response()) {
          on_success_();
        } else {
          // TODO custom error_code (this one is defaulted to indicate no error)
          on_error_(ec);
        }
      }
    }
  private:
    endpoint_type endpoint_;
    session_data& session_;
    socket_type& socket_;
    OnSuccess on_success_;
    OnError on_error_;
  };
}}
