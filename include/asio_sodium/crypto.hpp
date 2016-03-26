#ifndef ASIO_SODIUM_75226a68_a8b1_4eba_839c_08df9c278729
#define ASIO_SODIUM_75226a68_a8b1_4eba_839c_08df9c278729

#include <array>
#include <sodium.h>
#include <span.h>

namespace asio_sodium {
  using byte = unsigned char;
  using public_key = std::array<byte, crypto_box_PUBLICKEYBYTES>;
  using private_key = std::array<byte, crypto_box_SECRETKEYBYTES>;
  using nonce = std::array<byte, crypto_box_NONCEBYTES>;
  using mac = std::array<byte, crypto_box_MACBYTES>;
  using public_key_span = gsl::span<byte, crypto_box_PUBLICKEYBYTES>;
  using private_key_span = gsl::span<byte, crypto_box_SECRETKEYBYTES>;
  using nonce_span = gsl::span<byte, crypto_box_NONCEBYTES>;
  using mac_span = gsl::span<byte, crypto_box_MACBYTES>;
}

#endif
