#include "asio_sodium/detail/handshake_hello.hpp"

#include <catch.hpp>

using namespace asio_sodium;

SCENARIO("handshake hello encrypt/decrypt", "[integration]") {
  detail::handshake_hello::buffer buffer;
  detail::handshake_hello hello{buffer};

  private_key server_sk;
  public_key server_pk;
  crypto_box_keypair(&server_pk[0], &server_sk[0]);

  private_key client_sk;
  public_key client_pk;
  crypto_box_keypair(&client_pk[0], &client_sk[0]);

  hello.set_public_key(client_pk);
  hello.generate_reply_nonce();
  nonce reply_nonce;
  hello.copy_reply_nonce(reply_nonce);
  REQUIRE( hello.encrypt_to(server_pk) );
  auto decrypted =
    detail::handshake_hello::decrypt(
      buffer
    , server_pk
    , server_sk
    )
  ;
  REQUIRE( decrypted );
  auto result_pk = decrypted->public_key_span();
  REQUIRE(
    std::equal(
      result_pk.begin()
    , result_pk.end()
    , client_pk.begin()
    )
  );
  auto result_nonce = decrypted->reply_nonce_span();
  REQUIRE(
    std::equal(
      result_nonce.begin()
    , result_nonce.end()
    , reply_nonce.begin()
    )
  );
}
