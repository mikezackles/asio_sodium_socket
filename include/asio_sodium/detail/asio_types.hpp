#pragma once

#include <asio/generic/stream_protocol.hpp>

namespace asio_sodium {
namespace detail {
  using socket_type = asio::generic::stream_protocol::socket;
  using endpoint_type = asio::generic::stream_protocol::endpoint;
}}
