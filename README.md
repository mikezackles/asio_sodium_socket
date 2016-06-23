[![Build Status](https://travis-ci.org/mikezackles/asio_sodium_socket.svg?branch=master)](https://travis-ci.org/mikezackles/asio_sodium_socket)

This is a header-only C++14 library implementing custom transport encryption
using libsodium and Asio's stackless coroutines. It assumes pre-shared public
keys and uses only the
[sealed box](https://download.libsodium.org/doc/public-key_cryptography/sealed_boxes.html)
and
[crypto box](https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html)
constructs.

Usage
-

This library depends on [Asio](http://think-async.com/),
[libsodium](https://download.libsodium.org/doc/), Microsoft's
[Guideline Support Library](https://github.com/Microsoft/GSL), and the
[reference implementation](https://github.com/akrzemi1/Optional) for
std::experimental::optional. Aside from libsodium, these dependencies are
bundled as submodules in the bundle directory. To use this library, just add the
appropriate bundled include directories to your project along with the primary
include directory. You will also need to install and link against libsodium.

The included CMakeLists.txt specifies an interface for the `asio_sodium_socket`
library, which should make things easier for cmake users. Note that if you'd
like to use your own copies of the dependencies, the `ASIO_LOCATION`,
`GSL_LOCATION`, and `OPTIONAL_LOCATION` cache variables are available.

For a usage example, see the [socket test](test/socket.cpp). Note that this
library only supports in-order transports (e.g. tcp or domain sockets).

Running the Tests
-

```shell
git clone --recursive git://github.com/mikezackles/asio_sodium_socket && cd asio_sodium_socket
cmake . && make && ctest
```

Authentication
-

Using the server's public key, the client sends a fixed-length sealed box
containing the client's public key and a random reply nonce. If the public key
retrieved from the sealed box is unknown, the connection is terminated.

The server uses the reply nonce to respond with a crypto box containing a reply
nonce and a followup nonce. The reply nonce is used for the client's next
transmission, and the followup nonce is used for the server's next transmission.

Communication
-

Subsequent messages consist of a fixed-length message header followed by
variable-length message data. A message header contains the length of the
following message data along with the random data nonce used to encrypt the
message data and a random followup nonce that will be used to encrypt the next
message header. The message length is sent in little-endian format.
