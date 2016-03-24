#include "asio_sodium/detail/handshake_response.hpp"

#include <catch.hpp>

using namespace asio_sodium;

SCENARIO("handshake response encrypt/decrypt", "[integration]") {
  detail::handshake_response::buffer buffer;
  detail::handshake_response response{buffer};

  private_key server_sk;
  public_key server_pk;
  crypto_box_keypair(&server_pk[0], &server_sk[0]);

  private_key client_sk;
  public_key client_pk;
  crypto_box_keypair(&client_pk[0], &client_sk[0]);

  response.generate_reply_nonce();
  response.generate_followup_nonce();
  nonce reply_nonce;
  nonce followup_nonce;
  response.copy_reply_nonce(reply_nonce);
  response.copy_followup_nonce(followup_nonce);
  nonce encrypt_nonce;
  randombytes_buf(&encrypt_nonce[0], encrypt_nonce.size());
  REQUIRE(
    response.encrypt_to(
      encrypt_nonce
    , client_pk
    , server_sk
    )
  );
  auto decrypted =
    detail::handshake_response::decrypt(
      buffer
    , encrypt_nonce
    , server_pk
    , client_sk
    )
  ;
  REQUIRE( decrypted );
  auto result_reply_nonce = decrypted->reply_nonce_span();
  REQUIRE(
    std::equal(
      result_reply_nonce.begin()
    , result_reply_nonce.end()
    , reply_nonce.begin()
    )
  );
  auto result_followup_nonce = decrypted->followup_nonce_span();
  REQUIRE(
    std::equal(
      result_followup_nonce.begin()
    , result_followup_nonce.end()
    , followup_nonce.begin()
    )
  );
}
