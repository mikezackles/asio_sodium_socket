#include "asio_sodium/detail/message_header.hpp"

#include <catch.hpp>

using namespace asio_sodium;

SCENARIO("message header encrypt/decrypt", "[integration]") {
  detail::message_header::buffer buffer;
  detail::message_header header{buffer};

  private_key remote_sk;
  public_key remote_pk;
  crypto_box_keypair(&remote_pk[0], &remote_sk[0]);

  private_key local_sk;
  public_key local_pk;
  crypto_box_keypair(&local_pk[0], &local_sk[0]);

  header.generate_data_nonce();
  header.generate_followup_nonce();
  header.set_message_length(42);
  nonce data_nonce;
  nonce followup_nonce;
  header.copy_data_nonce(data_nonce);
  header.copy_followup_nonce(followup_nonce);
  nonce encrypt_nonce;
  randombytes_buf(&encrypt_nonce[0], encrypt_nonce.size());
  REQUIRE(
    header.encrypt_to(
      encrypt_nonce
    , remote_pk
    , local_sk
    )
  );
  auto decrypted =
    detail::message_header::decrypt(
      buffer
    , encrypt_nonce
    , local_pk
    , remote_sk
    )
  ;
  REQUIRE( decrypted );
  auto result_data_nonce = decrypted->data_nonce_span();
  REQUIRE(
    std::equal(
      result_data_nonce.begin()
    , result_data_nonce.end()
    , data_nonce.begin()
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
  REQUIRE( decrypted->message_length() == 42 );
}
