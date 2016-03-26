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

#ifndef ASIO_SODIUM_101d0035_8812_49b9_9964_c98446206ed3
#define ASIO_SODIUM_101d0035_8812_49b9_9964_c98446206ed3

#include "detail/asio_types.hpp"
#include "detail/client_handshake.hpp"
#include "detail/message_reader.hpp"
#include "detail/message_writer.hpp"
#include "detail/server_handshake.hpp"
#include "detail/session_data.hpp"
#include "detail/tuple_index_sequence.hpp"

#include <asio/basic_socket_acceptor.hpp>
#include <asio/io_service.hpp>

namespace asio_sodium {
  class crypto_socket final {
  public:
    using socket_type = detail::socket_type;
    using endpoint_type = detail::endpoint_type;

    template <
      typename OnError
    , typename OnSuccess
    >
    static void
    async_connect(
      endpoint_type endpoint
    , asio::io_service& io
    , public_key const& remote_public_key
    , public_key const& local_public_key
    , private_key const& local_private_key
    , OnSuccess on_success
    , OnError on_error
    ) {
      auto movable = std::make_unique<movable_data>(
        std::piecewise_construct
      , socket_type(io)
      , std::forward_as_tuple(
          remote_public_key
        , local_public_key
        , local_private_key
        )
      );

      auto& session = movable->session;
      auto& socket = movable->socket;
      auto on_handshake =
        [ movable = std::move(movable)
        , on_success = std::move(on_success)
        ] ()
        mutable {
          on_success(crypto_socket(std::move(movable)));
        }
      ;
      detail::client_handshake<decltype(on_handshake), OnError>(
        std::move(endpoint)
      , session
      , socket
      , std::move(on_handshake)
      , std::move(on_error)
      )();
    }

    template <
      // TODO - need a concept to check that the protocol guarantees in-order
      // delivery
      typename AsioProtocol
    , typename Authenticator
    , typename OnSuccess
    , typename OnError
    >
    static void
    async_accept(
      asio::io_service& io
    , asio::basic_socket_acceptor<AsioProtocol>& acceptor
    , public_key const& local_public_key
    , private_key const& local_private_key
    , Authenticator authenticator
    , OnSuccess on_success
    , OnError on_error
    ) {
      auto movable = std::make_unique<movable_data>(
        std::piecewise_construct
      , socket_type(io)
      , std::forward_as_tuple(
          local_public_key
        , local_private_key
        )
      );

      auto& session = movable->session;
      auto& socket = movable->socket;
      auto on_handshake =
        [ movable = std::move(movable)
        , on_success = std::move(on_success)
        ] ()
        mutable {
          on_success(crypto_socket(std::move(movable)));
        }
      ;
      auto on_accept =
        detail::server_handshake<
          Authenticator, decltype(on_handshake), OnError
        >(
          session
        , socket
        , std::move(authenticator)
        , std::move(on_handshake)
        , std::move(on_error)
        )
      ;
      acceptor.async_accept(
        socket
      , std::move(on_accept)
      );
    }

    template <
      typename ReadHandler
    >
    void
    async_read(
      gsl::span<byte> buffer
    , ReadHandler&& handler
    ) {
      detail::message_reader<ReadHandler>(
        buffer
      , movable_->socket
      , movable_->session
      , std::forward<ReadHandler>(handler)
      )();
    }

    template <
      typename WriteHandler
    >
    void
    async_write_destructive(
      gsl::span<byte> buffer
    , WriteHandler&& handler
    ) {
      detail::message_writer<WriteHandler>(
        buffer
      , movable_->socket
      , movable_->session
      , std::forward<WriteHandler>(handler)
      )();
    }

  private:
    struct movable_data {
      template <typename CryptoArgs>
      explicit movable_data(
        std::piecewise_construct_t
      , socket_type&& socket_
      , CryptoArgs&& crypto_args_
      )
        : movable_data(
            std::move(socket_)
          , std::move(crypto_args_)
          , detail::tuple_index_sequence<CryptoArgs>()
          )
      {}

      socket_type socket;
      detail::session_data session;

    private:
      template <
        typename ...CryptoArgs
      , std::size_t ...CryptoIndices
      >
      explicit movable_data(
        socket_type&& socket_
      , std::tuple<CryptoArgs...>&& crypto_args_
      , std::index_sequence<CryptoIndices...>
      )
        : socket(std::move(socket_))
        , session(
            std::forward<CryptoArgs>(
              std::get<CryptoIndices>(crypto_args_)
            )...
          )
      {}

    };

    crypto_socket(
      std::unique_ptr<movable_data> movable
    )
      : movable_(std::move(movable))
    {}

    // This is essential so that asio async callbacks don't end up with a
    // dangling socket reference if this instance is moved.
    std::unique_ptr<movable_data> movable_;
  };
}

#endif
