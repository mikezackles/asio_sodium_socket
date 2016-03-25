#pragma once

namespace asio_sodium {
  enum class error {
    handshake_hello_encrypt
  , handshake_hello_decrypt
  , handshake_authentication
  , handshake_response_encrypt
  , handshake_response_decrypt
  , message_header_encrypt
  , message_header_decrypt
  , message_too_large
  , message_encrypt
  , message_decrypt
  };

  class error_category
    : public std::error_category
  {
  public:
    char const* name() const noexcept override {
      return "asio_sodium errors";
    }
    std::string message(int ev) const override {
      auto e = static_cast<error>(ev);
      switch (e) {
      case error::handshake_hello_encrypt:
        return "Couldn't encrypt handshake hello";
      case error::handshake_hello_decrypt:
        return "Couldn't decrypt handshake hello";
      case error::handshake_authentication:
        return "Handshake failed to authenticate";
      case error::handshake_response_encrypt:
        return "Couldn't encrypt handshake response";
      case error::handshake_response_decrypt:
        return "Couldn't decrypt handshake response";
      case error::message_header_encrypt:
        return "Couldn't encrypt message header";
      case error::message_header_decrypt:
        return "Couldn't decrypt message header";
      case error::message_too_large:
        return "Message too large";
      case error::message_encrypt:
        return "Couldn't encrypt message";
      case error::message_decrypt:
        return "Couldn't decrypt message";
      }
    }
  };

  inline
  std::error_category const&
  get_error_category() {
    static error_category cat;
    return cat;
  }

  inline
  std::error_code
  make_error_code(error e) {
    return std::error_code(
      static_cast<int>(e)
    , get_error_category()
    );
  }
}

// Specialize std::is_error_code_enum to indicate that errors is an
// error_code_enum
namespace std {
  template<> struct is_error_code_enum<asio_sodium::error>
    : public std::true_type
  {};
}
