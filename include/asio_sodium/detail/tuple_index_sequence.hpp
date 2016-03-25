#pragma once

namespace asio_sodium {
namespace detail {
  template <typename Tuple>
  constexpr inline auto
  tuple_index_sequence() {
    return
      std::make_index_sequence<
        std::tuple_size<
          typename std::decay<Tuple>::type
        >::value
      >{}
    ;
  }
}}
