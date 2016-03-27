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
  auto result_pk = decrypted->client_public_key_span();
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
