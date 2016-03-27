[![Build Status](https://travis-ci.org/mikezackles/asio_sodium_socket.svg?branch=master)](https://travis-ci.org/mikezackles/asio_sodium_socket)

asio_sodium_socket implements custom transport encryption using libsodium. It
assumes pre-shared public keys and uses only the sealed box and crypto box
constructs.

Authentication
-

Using the server's public key, the client sends a fixed-length sealed box
containing the client's public key and a random *reply nonce*. If the public key
retrieved from the sealed box is unknown, the connection is terminated.

The server uses the reply nonce to respond with a crypto box containing a *reply
nonce* and a *followup nonce*. The reply nonce is used for the client's next
transmission, and the followup nonce is used for the server's next transmission.

Communication
-

Subsequent messages consist of a fixed-length *message header* followed by
variable-length *message data*. A message header contains the length of the
following message data along with the random *data nonce* used to encrypt the
message data and a random *followup nonce* that will be used to encrypt the next
message header. The message length is sent in little-endian format.

Notes
-

With a bit of work, keys could be ratcheted with each transmission.
