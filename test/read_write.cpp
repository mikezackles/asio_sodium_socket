#include "asio_sodium/crypto.hpp"
#include "asio_sodium/detail/session_data.hpp"
#include "asio_sodium/detail/message_reader.hpp"
#include "asio_sodium/detail/message_writer.hpp"

#include <asio/io_service.hpp>
#include <asio/ip/tcp.hpp>
#include <catch.hpp>
#include <sodium.h>

#include <iostream>

using namespace asio_sodium;

SCENARIO("message transmission", "[integration]") {
  private_key server_sk;
  public_key server_pk;
  crypto_box_keypair(&server_pk[0], &server_sk[0]);

  private_key client_sk;
  public_key client_pk;
  crypto_box_keypair(&client_pk[0], &client_sk[0]);

  detail::session_data client_session{server_pk, client_pk, client_sk};
  // This constructor is usually for the client, but I'm using it to simulate
  // successful authentication. (The handshake process doesn't write the client
  // public key until after authentication.)
  detail::session_data server_session{client_pk, server_pk, server_sk};

  // Simulate a successful handshake
  // (Each side's encrypt nonce should match the other side's decrypt nonce, and
  // vice versa.)
  nonce nonce1;
  randombytes_buf(&nonce1[0], nonce1.size());
  std::copy(
    nonce1.begin()
  , nonce1.end()
  , client_session.encrypt_nonce.begin()
  );
  std::copy(
    nonce1.begin()
  , nonce1.end()
  , server_session.decrypt_nonce.begin()
  );
  nonce nonce2;
  randombytes_buf(&nonce2[0], nonce2.size());
  std::copy(
    nonce2.begin()
  , nonce2.end()
  , server_session.encrypt_nonce.begin()
  );
  std::copy(
    nonce2.begin()
  , nonce2.end()
  , client_session.decrypt_nonce.begin()
  );

  asio::io_service io;
  asio::ip::tcp::acceptor acceptor{
    io
  , asio::ip::tcp::endpoint{asio::ip::tcp::v4(), 58008}
  };

  std::array<byte, 42> original_message;
  randombytes_buf(&original_message[0], original_message.size());
  std::array<byte, 42> source_message;
  std::copy(
    original_message.begin()
  , original_message.end()
  , source_message.begin()
  );
  std::array<byte, 42> target_message;

  bool server_success = false;
  bool server_error = false;
  auto server_socket = detail::socket_type(asio::ip::tcp::socket(io));
  acceptor.async_accept(
    server_socket
  , [ &server_socket
    , &server_success
    , &server_error
    , &server_session
    , &target_message
    ](auto) {
      auto server_callback = [
        &server_success
      , &server_error
      , &server_socket
      ](auto ec, auto) {
        if (ec) {
          std::cout << "SERVER ERROR: " << ec.message() << std::endl;
          server_error = true;
          server_socket.shutdown(
            asio::generic::stream_protocol::socket::shutdown_both
          );
        } else {
          server_success = true;
        }
      };
      detail::message_reader<decltype(server_callback)>(
        gsl::as_span<byte>(target_message)
      , server_socket
      , server_session
      , std::move(server_callback)
      )();
    }
  );

  bool client_success = false;
  bool client_error = false;
  auto client_socket = detail::socket_type(asio::ip::tcp::socket(io));
  client_socket.async_connect(
    detail::endpoint_type(asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 58008))
  , [ &client_success
    , &client_error
    , &client_socket
    , &client_session
    , &source_message
    ](auto) {
      auto client_callback = [
        &client_success
      , &client_error
      , &client_socket
      ](auto ec, auto) {
        if (ec) {
          std::cout << "CLIENT ERROR: " << ec.message() << std::endl;
          client_error = true;
          client_socket.shutdown(
            asio::generic::stream_protocol::socket::shutdown_both
          );
        } else {
          client_success = true;
        }
      };
      detail::message_writer<decltype(client_callback)>(
        gsl::as_span(source_message)
      , client_socket
      , client_session
      , std::move(client_callback)
      )();
    }
  );

  io.run();

  REQUIRE( server_success );
  REQUIRE( !server_error );
  REQUIRE( client_success );
  REQUIRE( !client_error );
  REQUIRE(
    std::equal(
      original_message.begin()
    , original_message.end()
    , target_message.begin()
    )
  );
}
