#include "asio_sodium/crypto.hpp"
#include "asio_sodium/detail/session_data.hpp"

#include <catch.hpp>
#include <sodium.h>

using namespace asio_sodium;

#define UNUSED(x) (void)(x)
SCENARIO("full handshake", "[integration]") {
  private_key server_sk;
  public_key server_pk;
  crypto_box_keypair(&server_pk[0], &server_sk[0]);

  private_key client_sk;
  public_key client_pk;
  crypto_box_keypair(&client_pk[0], &client_sk[0]);

  detail::session_data client_session(server_pk, client_pk, client_sk);
  detail::session_data server_session(server_pk, server_pk);
  UNUSED(client_session);
  UNUSED(server_session);
}
