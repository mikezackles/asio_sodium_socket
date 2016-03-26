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
