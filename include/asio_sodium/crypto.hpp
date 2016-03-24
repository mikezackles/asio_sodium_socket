#pragma once

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
