#include "asio_sodium/crypto.hpp"
#include "asio_sodium/detail/client_handshake.hpp"
#include "asio_sodium/detail/server_handshake.hpp"
#include "asio_sodium/detail/session_data.hpp"

#include <asio/io_service.hpp>
#include <asio/ip/tcp.hpp>
#include <catch.hpp>
#include <sodium.h>

using namespace asio_sodium;

SCENARIO("full handshake", "[integration]") {
  private_key server_sk;
  public_key server_pk;
  crypto_box_keypair(&server_pk[0], &server_sk[0]);

  private_key client_sk;
  public_key client_pk;
  crypto_box_keypair(&client_pk[0], &client_sk[0]);

  detail::session_data client_session{server_pk, client_pk, client_sk};
  detail::session_data server_session{server_pk, server_sk};

  asio::io_service io;
  asio::basic_socket_acceptor<asio::ip::tcp> acceptor{
    asio::ip::tcp::acceptor{
      io
    , asio::ip::tcp::endpoint{asio::ip::tcp::v4(), 58008}
    }
  };
  bool server_success = false;
  bool server_error = false;
  auto server_socket = detail::socket_type(asio::ip::tcp::socket(io));
  acceptor.async_accept(
    server_socket
  , [ &server_socket
    , &server_success
    , &server_error
    , &server_session
    ](auto) {
      auto authenticator = [](auto const) { return true; };
      auto on_success = [&server_success]() {
        server_success = true;
      };
      auto on_error = [
        &server_error
      , &server_socket
      ](auto, auto) {
        server_socket.shutdown(
          asio::generic::stream_protocol::socket::shutdown_both
        );
        server_error = true;
      };
      detail::server_handshake<
        decltype(authenticator)
      , decltype(on_success)
      , decltype(on_error)
      >(
        server_session
      , server_socket
      , std::move(authenticator)
      , std::move(on_success)
      , std::move(on_error)
      )();
    }
  );

  bool client_success = false;
  bool client_error = false;
  auto client_socket = detail::socket_type(asio::ip::tcp::socket(io));
  auto on_success = [&client_success]() {
    client_success = true;
  };
  auto on_error = [
    &client_error
  , &client_socket
  ](auto) {
    client_socket.shutdown(
      asio::generic::stream_protocol::socket::shutdown_both
    );
    client_error = true;
  };
  detail::client_handshake<
    decltype(on_success)
  , decltype(on_error)
  >(
    detail::endpoint_type(asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 58008))
  , client_session
  , client_socket
  , std::move(on_success)
  , std::move(on_error)
  )();

  io.run();

  REQUIRE( server_success );
  REQUIRE( !server_error );
  REQUIRE( client_success );
  REQUIRE( !client_error );
}
