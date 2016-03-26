#ifndef ASIO_SODIUM_76c5499a_db79_4b00_bda0_69b00c0b5dc6
#define ASIO_SODIUM_76c5499a_db79_4b00_bda0_69b00c0b5dc6

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

#endif
