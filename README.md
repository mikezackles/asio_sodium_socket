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

For a usage example, see the [socket test](test/socket.cpp).

Tests
-

The project is currently built using the Chromium project's
[Generate Ninja](https://chromium.googlesource.com/chromium/src/tools/gn/).
There is a PKGBUILD for Arch Linux
[here](https://github.com/mikezackles/gn-git). You will also need to install the
[Ninja build system](https://ninja-build.org/).

To build and run the tests:

```shell
gn gen out/release --args="is_debug=false"
ninja -C out/release
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

Notes
-

With a bit of work, keys could be ratcheted with each transmission.
