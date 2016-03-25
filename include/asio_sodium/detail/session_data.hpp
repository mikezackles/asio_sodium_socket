#pragma once

#include "../crypto.hpp"
#include "asio_types.hpp"
#include "handshake_hello.hpp"
#include "handshake_response.hpp"
#include "message_header.hpp"

#include <asio/read.hpp>
#include <asio/write.hpp>
#include <optional.hpp>

namespace asio_sodium {
namespace detail {
  class session_data {
  public:
    explicit
    session_data(
      public_key const& remote_public_key
    , public_key const& local_public_key
    , private_key const& local_private_key
    )
    noexcept
      : remote_public_key_(remote_public_key)
      , local_public_key_(local_public_key)
      , local_private_key_(local_private_key)
    {}

    explicit
    session_data(
      public_key const& local_public_key
    , private_key const& local_private_key
    )
    noexcept
      : local_public_key_(local_public_key)
      , local_private_key_(local_private_key)
    {}

    void
    make_hello()
    noexcept {
      handshake_hello hello(hello_buffer_);
      hello.set_public_key(local_public_key_);
      hello.generate_reply_nonce();
      hello.copy_reply_nonce(decrypt_nonce_);
      hello.encrypt_to(remote_public_key_);
    }

    template <typename Callback>
    void
    send_hello(socket_type& socket, Callback&& callback)
    noexcept {
      asio::async_write(
        socket
      , asio::buffer(hello_buffer_)
      , std::forward<Callback>(callback)
      );
    }

    template <typename Callback>
    void
    await_hello(socket_type& socket, Callback&& callback)
    noexcept {
      asio::async_read(
        socket
      , asio::buffer(hello_buffer_)
      , std::forward<Callback>(callback)
      );
    }

    template <typename Auth>
    bool
    process_hello(Auth&& auth)
    noexcept {
      auto hello =
        handshake_hello::decrypt(
          hello_buffer_
        , local_public_key_
        , local_private_key_
        )
      ;
      if (!hello) {
        return false;
      }
      auto public_key = hello->public_key_span();
      // Look up the public key and make sure it's authorized
      if (!auth(public_key)) {
        return false;
      }
      std::copy(
        public_key.begin()
      , public_key.end()
      , remote_public_key_.begin()
      );
      hello->copy_reply_nonce(encrypt_nonce_);
      return true;
    }

    bool
    make_hello_response()
    noexcept {
      handshake_response response{hello_response_buffer_};

      response.generate_reply_nonce();
      response.copy_reply_nonce(decrypt_nonce_);

      nonce temp_followup_nonce;

      response.generate_followup_nonce();
      response.copy_followup_nonce(temp_followup_nonce);

      if (
        !response.encrypt_to(
          encrypt_nonce_
        , remote_public_key_
        , local_private_key_
        )
      ) {
        return false;
      }

      std::copy(
        temp_followup_nonce.begin()
      , temp_followup_nonce.end()
      , encrypt_nonce_.begin()
      );

      return true;
    }

    template <typename Callback> void
    send_hello_response(
      socket_type& socket, Callback&& callback
    )
    noexcept {
      asio::async_write(
        socket
      , asio::buffer(hello_response_buffer_)
      , std::forward<Callback>(callback)
      );
    }

    template <typename Callback> void
    await_hello_response(
      socket_type& socket, Callback&& callback
    )
    noexcept {
      asio::async_read(
        socket
      , asio::buffer(hello_response_buffer_)
      , std::forward<Callback>(callback)
      );
    }

    bool
    process_hello_response()
    noexcept {
      auto response = handshake_response::decrypt(
        hello_response_buffer_
      , decrypt_nonce_
      , remote_public_key_
      , local_private_key_
      );

      if (!response) {
        return false;
      }

      response->copy_reply_nonce(encrypt_nonce_);
      response->copy_followup_nonce(decrypt_nonce_);

      return true;
    }

    // Call this and then send the header buffer, the mac, and the encrypted
    // message, in that order.
    bool
    encrypt_message(
      gsl::span<byte> plaintext // encrypts plaintext in-place
    )
    noexcept {
      message_header header(header_buffer_);
      header.generate_data_nonce();
      header.generate_followup_nonce();
      header.set_message_length(plaintext.length());

      auto data_nonce = header.data_nonce_span();
      if (
        !crypto_box_detached(
          &plaintext[0]
        , &mac_[0]
        , &plaintext[0]
        , plaintext.size()
        , &data_nonce[0]
        , &remote_public_key_[0]
        , &local_private_key_[0]
        )
      ) {
        return false;
      }

      if (
        !header.encrypt_to(
          encrypt_nonce_
        , remote_public_key_
        , local_private_key_
        )
      ) {
        return false;
      }

      header.copy_followup_nonce(encrypt_nonce_);

      return true;
    }

    template <typename Callback>
    void
    send_header(
      socket_type& socket, Callback&& callback
    )
    noexcept {
      asio::async_write(
        socket
      , asio::buffer(header_buffer_)
      , std::forward<Callback>(callback)
      );
    }

    template <typename Callback>
    void
    send_mac(
      socket_type& socket, Callback&& callback
    )
    noexcept {
      asio::async_write(
        socket
      , asio::buffer(mac_)
      , std::forward<Callback>(callback)
      );
    }

    template <typename Callback>
    void
    read_header(
      socket_type& socket, Callback&& callback
    )
    noexcept {
      asio::async_read(
        socket
      , asio::buffer(header_buffer_)
      , std::forward<Callback>(callback)
      );
    }

    std::experimental::optional<uint32_t>
    process_header() {
      auto const header = message_header::decrypt(
        header_buffer_
      , decrypt_nonce_
      , remote_public_key_
      , local_private_key_
      );

      if (!header) {
        return {};
      }

      return header->message_length();
    }

    template <typename Callback>
    void
    read_mac(
      socket_type& socket, Callback&& callback
    )
    noexcept {
      asio::async_read(
        socket
      , asio::buffer(mac_)
      , std::forward<Callback>(callback)
      );
    }

    bool
    decrypt_message(
      gsl::span<byte> ciphertext // decrypts in-place
    )
    noexcept {
      message_header const header(
        header_buffer_
      );

      header.copy_followup_nonce(decrypt_nonce_);

      auto const data_nonce = header.data_nonce_span();
      return crypto_box_open_detached(
        &ciphertext[0]
      , &mac_[0]
      , &ciphertext[0]
      , ciphertext.size()
      , &data_nonce[0]
      , &remote_public_key_[0]
      , &local_private_key_[0]
      );
    }

  private:
    nonce decrypt_nonce_;
    nonce encrypt_nonce_;
    public_key remote_public_key_;
    public_key local_public_key_;
    // TODO - wipe on destruct!
    private_key local_private_key_;
    mac mac_;
    handshake_hello::buffer hello_buffer_;
    handshake_response::buffer hello_response_buffer_;
    message_header::buffer header_buffer_;
  };
}}
