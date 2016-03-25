#include "asio_sodium/crypto_socket.hpp"

#include <asio/coroutine.hpp>
#include <asio/io_service.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/yield.hpp>
#include <catch.hpp>
#include <sodium.h>

#include <iostream>

using namespace asio_sodium;

namespace {
  class server : asio::coroutine {
  public:
    server(
      crypto_socket&& socket
    , gsl::span<byte> source1
    , gsl::span<byte> target2
    , gsl::span<byte> source3
    )
      : socket_(std::move(socket))
      , source1_(source1)
      , target2_(target2)
      , source3_(source3)
    {}

    void
    operator()(
      std::error_code ec = std::error_code()
    , std::size_t = 0
    ) {
      if (ec) {
        std::cout << "SERVER ERROR: " << ec.message() << std::endl;
        return;
      }

      reenter (this) {
        yield socket_.async_write_destructive(
          source1_
        , std::move(*this)
        );
        yield socket_.async_read(target2_, std::move(*this));
        yield socket_.async_write_destructive(
          source3_
        , std::move(*this)
        );
      }
    }
  private:
    crypto_socket socket_;
    gsl::span<byte> source1_;
    gsl::span<byte> target2_;
    gsl::span<byte> source3_;
  };

  class client : asio::coroutine {
  public:
    client(
      crypto_socket&& socket
    , gsl::span<byte> target1
    , gsl::span<byte> source2
    , gsl::span<byte> target3
    )
      : socket_(std::move(socket))
      , target1_(target1)
      , source2_(source2)
      , target3_(target3)
    {}

    void
    operator()(
      std::error_code ec = std::error_code()
    , std::size_t = 0
    ) {
      if (ec) {
        std::cout << "CLIENT ERROR: " << ec.message() << std::endl;
        return;
      }

      reenter (this) {
        yield socket_.async_read(target1_, std::move(*this));
        yield socket_.async_write_destructive(
          source2_
        , std::move(*this)
        );
        yield socket_.async_read(target3_, std::move(*this));
      }
    }
  private:
    crypto_socket socket_;
    gsl::span<byte> target1_;
    gsl::span<byte> source2_;
    gsl::span<byte> target3_;
  };
}

SCENARIO("socket repeated read/write", "[integration]") {
  private_key server_sk;
  public_key server_pk;
  crypto_box_keypair(&server_pk[0], &server_sk[0]);

  private_key client_sk;
  public_key client_pk;
  crypto_box_keypair(&client_pk[0], &client_sk[0]);

  asio::io_service io;
  asio::ip::tcp::acceptor acceptor{
    io
  , asio::ip::tcp::endpoint{asio::ip::tcp::v4(), 58008}
  };

  // message 1
  std::array<byte, 1000> original_message1;
  randombytes_buf(&original_message1[0], original_message1.size());
  std::array<byte, 1000> source_message1;
  std::copy(
    original_message1.begin()
  , original_message1.end()
  , source_message1.begin()
  );
  std::array<byte, 1000> target_message1;

  // message 2
  std::array<byte, 37> original_message2;
  randombytes_buf(&original_message2[0], original_message2.size());
  std::array<byte, 37> source_message2;
  std::copy(
    original_message2.begin()
  , original_message2.end()
  , source_message2.begin()
  );
  std::array<byte, 37> target_message2;

  // message 3
  std::array<byte, 2345> original_message3;
  randombytes_buf(&original_message3[0], original_message3.size());
  std::array<byte, 2345> source_message3;
  std::copy(
    original_message3.begin()
  , original_message3.end()
  , source_message3.begin()
  );
  std::array<byte, 2345> target_message3;

  auto authenticator = [](auto const) { return true; };
  auto on_success = [
    &source_message1
  , &target_message2
  , &source_message3
  ](auto&& server_socket) {
    server(
      std::move(server_socket)
    , source_message1
    , target_message2
    , source_message3
    )();
  };
  auto on_error = [](auto ec, auto) {
    std::cout << "ACCEPT ERROR: " << ec.message() << std::endl;
  };
  crypto_socket::async_accept(
    io
  , acceptor
  , server_pk
  , server_sk
  , std::move(authenticator)
  , std::move(on_success)
  , std::move(on_error)
  );

  auto on_connect_success = [
    &target_message1
  , &source_message2
  , &target_message3
  ](auto&& server_socket) {
    client(
      std::move(server_socket)
    , target_message1
    , source_message2
    , target_message3
    )();
  };
  auto on_connect_error = [](auto ec) {
    std::cout << "CONNECT ERROR: " << ec.message() << std::endl;
  };
  crypto_socket::async_connect(
    asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 58008)
  , io
  , server_pk
  , client_pk
  , client_sk
  , std::move(on_connect_success)
  , std::move(on_connect_error)
  );

  io.run();

  REQUIRE(
    std::equal(
      original_message1.begin()
    , original_message1.end()
    , target_message1.begin()
    )
  );
  REQUIRE(
    std::equal(
      original_message2.begin()
    , original_message2.end()
    , target_message2.begin()
    )
  );
  REQUIRE(
    std::equal(
      original_message3.begin()
    , original_message3.end()
    , target_message3.begin()
    )
  );
}
