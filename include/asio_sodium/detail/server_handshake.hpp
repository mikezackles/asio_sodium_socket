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

#ifndef ASIO_SODIUM_e50e3cf0_2e11_453d_bb1e_3f6ff09eca5d
#define ASIO_SODIUM_e50e3cf0_2e11_453d_bb1e_3f6ff09eca5d

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
        yield await_hello();
        ec = process_hello();
        if (ec) {
          on_error_(ec, bytes);
          yield break;
        }
        ec = make_hello_response();
        if (ec) {
          on_error_(ec, bytes);
          yield break;
        }
        yield send_hello_response();
        on_success_();
      }
    }

  private:
    void
    await_hello()
    noexcept {
      asio::async_read(
        socket_
      , asio::buffer(session_.hello_buffer)
      , std::move(*this)
      );
    }

    std::error_code
    process_hello()
    noexcept {
      auto hello =
        handshake_hello::decrypt(
          session_.hello_buffer
        , session_.local_public_key
        , session_.local_private_key
        )
      ;
      if (!hello) {
        return error::handshake_hello_decrypt;
      }
      auto public_key = hello->client_public_key_span();
      // Look up the public key and make sure it's authorized
      if (!authenticator_(public_key)) {
        return error::handshake_authentication;
      }
      std::copy(
        public_key.begin()
      , public_key.end()
      , session_.remote_public_key.begin()
      );
      hello->copy_reply_nonce(session_.encrypt_nonce);
      return {};
    }

    std::error_code
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
        return error::handshake_response_encrypt;
      }

      std::copy(
        temp_followup_nonce.begin()
      , temp_followup_nonce.end()
      , session_.encrypt_nonce.begin()
      );

      return {};
    }

    void
    send_hello_response()
    noexcept {
      asio::async_write(
        socket_
      , asio::buffer(session_.hello_response_buffer)
      , std::move(*this)
      );
    }

    session_data& session_;
    socket_type& socket_;
    Authenticator authenticator_;
    OnSuccess on_success_;
    OnError on_error_;
  };
}}

#endif
