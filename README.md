# sodium.cr

[![Crystal CI](https://github.com/didactic-drunk/sodium.cr/actions/workflows/crystal.yml/badge.svg)](https://github.com/didactic-drunk/sodium.cr/actions/workflows/crystal.yml)
[![GitHub release](https://img.shields.io/github/release/didactic-drunk/sodium.cr.svg)](https://github.com/didactic-drunk/sodium.cr/releases)
![GitHub commits since latest release (by date) for a branch](https://img.shields.io/github/commits-since/didactic-drunk/sodium.cr/latest)
[![Docs](https://img.shields.io/badge/docs-available-brightgreen.svg)](https://didactic-drunk.github.io/sodium.cr/master)

Crystal bindings for the [libsodium API](https://libsodium.gitbook.io/doc/)

> **This fork** is maintained at `https://github.com/OkaVatti/sodium.cr` and targets **libsodium ≥ 1.0.22**. It adds bindings for all APIs introduced up to libsodium 1.0.22, fixes deprecation warnings, and is tested against official libsodium test vectors where available.

## Goals

- Provide the most commonly used libsodium API's.
- Provide an easy to use API based on reviewing most other [libsodium bindings](https://libsodium.gitbook.io/doc/bindings_for_other_languages).
- Test for compatibility against other libsodium bindings to ensure interoperability.
- Always provide a stream interface to handle arbitrarily sized data when one is available.
- Drop in replacement classes compatible with OpenSSL::{Digest,Cipher} when possible.
- Use the newest system packaged libsodium or download the most recent stable version without manual configuration.

## Features

- [Public-Key Cryptography](https://libsodium.gitbook.io/doc/public-key_cryptography)
  - [x] [Crypto Box Easy](https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption)
  - [x] [Sealed Box](https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes)
  - [x] [Combined Signatures](https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures)
  - [x] [Detached Signatures](https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures)
  - [x] **[NEW]** [Pre-hashed Signatures (Ed25519ph)](https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures) – streaming pre-hashed signing/verification.
- [Secret-Key Cryptography](https://libsodium.gitbook.io/doc/secret-key_cryptography)
  - Secret Box
    - [x] [Combined mode](https://libsodium.gitbook.io/doc/secret-key_cryptography/authenticated_encryption)
    - [x] [Detached mode](https://libsodium.gitbook.io/doc/secret-key_cryptography/authenticated_encryption)
  - [x] [Secret Stream](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream)
  - [AEAD](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead)
  - [x] **[NEW]** AES256-GCM (Hardware-accelerated, falls back to software)
  - [x] [XChaCha20-Poly1305-IETF](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)
  - [x] **[NEW]** [ChaCha20-Poly1305-IETF](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/ietf_chacha20-poly1305_construction)
  - [x] **[NEW]** [ChaCha20-Poly1305 (original)](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305)
  - [x] Combined and detached mode
  - [x] **[NEW]** [AEGIS-128L / AEGIS-256](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/aegis) – high-speed AEAD ciphers (libsodium ≥ 1.0.19)
- [Hashing](https://libsodium.gitbook.io/doc/hashing)
  - [x] [Blake2b](https://libsodium.gitbook.io/doc/hashing/generic_hashing)
    - [x] Complete libsodium implementation including `key`, `salt`, `personal` and fully selectable output sizes.
  - [x] **[NEW]** [SipHash](https://libsodium.gitbook.io/doc/hashing/short-input_hashing) – fast keyed hash for short inputs.
  - [x] **[NEW]** [SHA-3](https://en.wikipedia.org/wiki/SHA-3) (SHA3-256, SHA3-512) one-shot hashing (libsodium ≥ 1.0.22)
  - [x] **[NEW]** [Extendable Output Functions (XOF)](https://libsodium.gitbook.io/doc/hashing) – SHAKE128, SHAKE256, TurboSHAKE128, TurboSHAKE256 with domain separation (libsodium ≥ 1.0.21)
- [Password Hashing](https://libsodium.gitbook.io/doc/password_hashing)
  - [x] [Argon2](https://libsodium.gitbook.io/doc/password_hashing/the_argon2i_function) (Use for new applications)
  - [x] **[NEW]** [Scrypt](https://libsodium.gitbook.io/doc/advanced/scrypt) (For compatibility with older applications)
- [Key Exchange](https://libsodium.gitbook.io/doc/key_exchange)
  - [x] **[NEW]** [Key Exchange (KX)](https://libsodium.gitbook.io/doc/key_exchange) – client/server session key derivation (libsodium ≥ 1.0.12)
- [Key Encapsulation](https://libsodium.gitbook.io/doc/key_encapsulation)
  - [x] **[NEW]** [X-Wing (hybrid PQ KEM)](https://libsodium.gitbook.io/doc/key_encapsulation) – combines ML-KEM768 with X25519 (libsodium ≥ 1.0.22)
  - [x] **[NEW]** [ML-KEM768](https://libsodium.gitbook.io/doc/key_encapsulation) – NIST-standardized post-quantum KEM (libsodium ≥ 1.0.22)
- Other
  - [x] [Key Derivation](https://libsodium.gitbook.io/doc/key_derivation)
  - [x] **[NEW]** [IP Address Encryption](https://libsodium.gitbook.io/doc/networking) – deterministic, length-preserving IPv4/IPv6 encryption (libsodium ≥ 1.0.21)
- [Advanced](https://libsodium.gitbook.io/doc/advanced)
  - [Stream Ciphers](https://libsodium.gitbook.io/doc/advanced/stream_ciphers)
    - [x] XSalsa20
    - [x] Salsa20
    - [x] XChaCha20
    - [x] ChaCha20 Ietf
    - [x] ChaCha20
    - [x] Easy to use methods available for use as a CSPRNG that are faster and safer than Crystal's. See `benchmarks/rand.out`.
  - [x] **[NEW]** [One time auth (Poly1305)](https://libsodium.gitbook.io/doc/advanced/poly1305) – single-use message authentication.
  - [x] **[NEW]** Padding – pad/unpad messages to block boundaries.
- **[NEW] Utilities & Helpers**
  - [x] Ed25519 ↔ Curve25519 key conversion (`Sodium::Sign::Curve25519Convert`, `Sodium::Sign::KeyExtraction`)
  - [x] Constant-time memory comparison, zero-testing, and increment (`Sodium::ConstantTime`)
  - [x] Hexadecimal and Base64 encoding/decoding via libsodium (`Sodium::Encoding`)
  - [x] Low-level Ed25519 scalar multiplication without clamping (`Sodium::ScalarmultEd25519Noclamp`)
- Library features
  - [x] Faster builds by requiring what you need (`require "sodium/secret_box"`)
  - [x] Nonce reuse detection.
  - [x] All SecretKey's held in libsodium guarded memory.
  - [x] No heap allocations after #initialize when possible.
  - [x] Fast. Benchmarks available in `benchmarks`.
  - [x] [Most classes are safe to share between threads.](THREAD_SAFETY.md)
    - [x] Tested with real crystal threads and will continue to work when crystal officially supports threading.
  - [ ] Controlled memory wiping (by calling `.close`)

> specs/tests are compared against official test vectors from libsodium.

Several features in libsodium are already provided by Crystal:

- Random (Use [Random::Secure](https://crystal-lang.org/api/latest/Random/Secure.html))
- SHA-2 (Use [OpenSSL::Digest](https://crystal-lang.org/api/latest/OpenSSL/Digest.html))
- HMAC SHA-2 (Use [OpenSSL::HMAC](https://crystal-lang.org/api/latest/OpenSSL/HMAC.html))
- Hex conversion (Use [String#hexbytes](https://crystal-lang.org/api/latest/String.html#hexbytes%3ABytes-instance-method))

## What should I use for my application?

| Class                                                                                                                                                                                                                    | Reason Behind Usage                                                                                           |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------- |
| Only use `CryptoBox::SecretKey` `Sign::SecretKey` `Aead::XChaCha20Poly1305Ietf` `SecretBox`                                                                                                                              | I don't know much about crypto.                                                                               |
| [`Sodium::CryptoBox::SecretKey`](https://didactic-drunk.github.io/sodium.cr/Sodium/CryptoBox/SecretKey.html) .box                                                                                                        | I want to encrypt + authenticate data using public key encryption.                                            |
| [`Sodium::CryptoBox::SecretKey`](https://didactic-drunk.github.io/sodium.cr/Sodium/CryptoBox/PublicKey.html) .encrypt                                                                                                    | I want anonymously send encrypted data. (No signatures)                                                       |
| [`Sodium::Sign::SecretKey`](https://didactic-drunk.github.io/sodium.cr/Sodium/Sign/SecretKey.html)                                                                                                                       | I want to sign or verify messages. (No encryption)                                                            |
| [`Sodium::Cipher::Aead::XChaCha20Poly1305Ietf` (new applications) `Sodium::SecretBox` (compatibility with older applications)](https://didactic-drunk.github.io/sodium.cr/Sodium/Cipher/Aead/XChaCha20Poly1305Ietf.html) | I have a shared key and want to encrypt + authenticate data.                                                  |
| [`Sodium::Cipher::Aead::XChaCha20Poly1305Ietf`](https://didactic-drunk.github.io/sodium.cr/Sodium/Cipher/Aead/XChaCha20Poly1305Ietf.html)                                                                                | I have a shared key and want to encrypt + authenticate data and authenticate additional plaintext data.       |
| [`Sodium::Cipher::SecretStream`](https://didactic-drunk.github.io/sodium.cr/Sodium/Cipher/SecretStream/XChaCha20Poly1305.html)                                                                                           | I have a shared key and want encrypt + authenticate streamed data.                                            |
| [`Sodium::Digest::Blake2b`](https://didactic-drunk.github.io/sodium.cr/Sodium/Digest/Blake2b.html)                                                                                                                       | I want to hash data fast and securely.                                                                        |
| `Sodium::Hash::SipHash`                                                                                                                                                                                                  | I want to hash data really fast and less securely. (Not implemented yet)                                      |
| `Sodium::Cipher::Aegis128L` or `Aegis256`                                                                                                                                                                                | I have a shared key, want the fastest AEAD on modern hardware, and can accept a slight portability trade-off. |
| [`Sodium::KX::Client` / `Sodium::KX::Server`](https://libsodium.gitbook.io/doc/key_exchange)                                                                                                                             | I want to derive shared session keys from long-term key pairs.                                                |
| [`Sodium::KEM`](https://libsodium.gitbook.io/doc/key_encapsulation)                                                                                                                                                      | I want post-quantum-safe key encapsulation (X-Wing or ML-KEM768).                                             |
| [`Sodium::SealedBox`](https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes)                                                                                                                             | I want anonymous public-key encryption (standalone).                                                          |
| [`Sodium::Hash::SHA3_256` / `SHA3_512`](https://en.wikipedia.org/wiki/SHA-3)                                                                                                                                             | I want a modern, FIPS-202 hash.                                                                               |
| [`Sodium::XOF::Shake128` / `Shake256` / `TurboShake128` / `TurboShake256`](https://libsodium.gitbook.io/doc/hashing)                                                                                                     | I need an extendable-output function for key derivation or post-quantum schemes.                              |
| [`Sodium::IPCrypt`](https://libsodium.gitbook.io/doc/networking)                                                                                                                                                         | I want to encrypt IP addresses in logs or network data.                                                       |
| [`Sodium::Password::Hash`](https://didactic-drunk.github.io/sodium.cr/Sodium/Password/Hash.html)                                                                                                                         | I want to hash a password and store it.                                                                       |
| [`Sodium::Password::Key`](https://didactic-drunk.github.io/sodium.cr/Sodium/Password/Key.html)                                                                                                                           | I want to derive a key from a password.                                                                       |
| `Sodium::Password::Scrypt`                                                                                                                                                                                               | I need scrypt for compatibility with older systems.                                                           |
| [`Sodium::Kdf`](https://didactic-drunk.github.io/sodium.cr/Sodium/Kdf.html)                                                                                                                                              | I have a high quality master key and want to make subkeys.                                                    |
| `Sodium::Cipher::Aead::ChaCha20Poly1305` or `ChaCha20Poly1305Ietf`                                                                                                                                                       | I need specific nonce sizes (8‑byte or 12‑byte) for interop.                                                  |
| `Sodium::Cipher::Aes256Gcm`                                                                                                                                                                                              | I need AES256-GCM (often hardware-accelerated).                                                               |
| `Sodium::Sign::PreHashed`                                                                                                                                                                                                | I want to stream a message and produce a pre-hashed Ed25519 signature.                                        |
| `Sodium::OneTimeAuth`                                                                                                                                                                                                    | I need a fast, single-use message authentication tag.                                                         |
| [`Sodium::Cipher::Chalsa`](https://didactic-drunk.github.io/sodium.cr/Sodium/Cipher/Chalsa.html)                                                                                                                         | What goes with guacamole?                                                                                     |
| Everything else                                                                                                                                                                                                          | I want to design my own crypto protocol and probably do it wrong.                                             |

## Installation

**[Optionally Install libsodium.](https://download.libsodium.org/doc/installation/)**
A recent version of libsodium is automatically downloaded and compiled if you don't install your own version.

Add this to your application's `shard.yml`:

```yaml
dependencies:
  sodium:
    github: OkaVatti/sodium.cr
```

> **For this fork**, replace the `github` line with the URL of your fork (e.g. `github: OkaVatti/sodium.cr`).  
> **System requirement**: libsodium ≥ 1.0.22 must be installed on the system (macOS: `brew install libsodium`; Linux: `apt install libsodium-dev` or equivalent). The build script links against the system library.

## Usage

See `examples` for help on using these classes in a complete application.

The `specs` provide the best examples of how to use or misuse individual classes.

---

### CryptoBox authenticated easy encryption

```crystal
require "sodium"

data = "Hello World!"

# Alice is the sender
alice = Sodium::CryptoBox::SecretKey.new

# Bob is the recipient
bob = Sodium::CryptoBox::SecretKey.new

# Precompute a shared secret between alice and bob.
box = alice.box bob.public_key

# Encrypt a message for Bob using his public key, signing it with Alice's
# secret key
encrypted, nonce = box.encrypt data

# Precompute within a block.  The shared secret is wiped when the block exits.
bob.box alice.public_key do |box|
  # Decrypt the message using Bob's secret key, and verify its signature against
  # Alice's public key
  decrypted = box.decrypt encrypted, nonce: nonce

  String.new(decrypted) # => "Hello World!"
end
```

### Unauthenticated public key encryption

```crystal
data = "Hello World!"

# Bob is the recipient
bob = Sodium::CryptoBox::SecretKey.new

# Encrypt a message for Bob using his public key
encrypted = bob.public_key.encrypt data

# Decrypt the message using Bob's secret key
decrypted = bob.decrypt encrypted
String.new(decrypted) # => "Hello World!"
```

### Public key signing

```crystal
message = "Hello World!"

secret_key = Sodium::Sign::SecretKey.new

# Sign the message
signature = secret_key.sign_detached message

# Send secret_key.public_key to the recipient

# On the recipient
public_key = Sodium::Sign::PublicKey.new key_bytes

# raises Sodium::Error::VerificationFailed on failure.
public_key.verify_detached message, signature
```

### Secret Key Encryption

```crystal
box = Sodium::SecretBox.new

message = "foobar"
encrypted, nonce = box.encrypt message

# On the other side.
box = Sodium::SecretKey.new key
message = box.decrypt encrypted, nonce: nonce
```

### Blake2b

```crystal
key = Bytes.new Sodium::Digest::Blake2B::KEY_SIZE
salt = Bytes.new Sodium::Digest::Blake2B::SALT_SIZE
personal = Bytes.new Sodium::Digest::Blake2B::PERSONAL_SIZE
out_size = 64 # bytes between Sodium::Digest::Blake2B::OUT_SIZE_MIN and Sodium::Digest::Blake2B::OUT_SIZE_MAX
data = "data".to_slice

# output_size, key, salt, and personal are optional.
digest = Sodium::Digest::Blake2b.new out_size, key: key, salt: salt, personal: personal
digest.update data
output = d.hexfinal

digest.reset # Reuse existing object to hash again.
digest.update data
output = d.hexfinal
```

### Key derivation

```crystal
kdf = Sodium::Kdf.new

# kdf.derive(8_byte_context, subkey_id, subkey_size)
subkey1 = kdf.derive "context1", 0, 16
subkey2 = kdf.derive "context1", 1, 16
subkey3 = kdf.derive "context2", 0, 32
subkey4 = kdf.derive "context2", 1, 64
```

### Password based keys

```crystal
pwcreate = Sodium::Password::Key::Create.new

# Take approximately 1 second to derive a key.
pwcreate.tcost = 1.0

pass = "1234"
key, params = pwcreate.create_key pass
# Store `params` or `params.to_h` for later.

# Derive the same key from the stored params.
pwkey = Sodium::Password::Key.from_params params.to_h
key = pekey.derive_key pass
```

### Password Hashing

```crystal
pwhash = Sodium::Password::Hash.new

pwhash.mem = Sodium::Password::MEMLIMIT_MIN
pwhash.ops = Sodium::Password::OPSLIMIT_MIN

pass = "1234"
hash = pwhash.create pass
pwhash.verify hash, pass
```

---

### Key Exchange (KX) **[NEW]**

```crystal
# Alice (client)
client = Sodium::KX::Client.new
# Bob (server)
server = Sodium::KX::Server.new

# Exchange public keys (out of band)
client_rx, client_tx = client.session_keys(server.public_key)
server_rx, server_tx = server.session_keys(client.public_key)

# Shared secrets are symmetric but swapped
client_rx == server_tx  # true – for client to receive from server
client_tx == server_rx  # true – for client to send to server
```

### Post-Quantum Key Encapsulation (KEM) **[NEW]**

```crystal
# Bob generates a long-term key pair
bob = Sodium::KEM::KeyPair.new

# Alice encapsulates a shared secret for Bob
ciphertext, alice_shared_secret = Sodium::KEM.encapsulate(bob.public_key)

# Bob decapsulates the ciphertext to recover the same secret
bob_shared_secret = Sodium::KEM.decapsulate(ciphertext, bob)

alice_shared_secret == bob_shared_secret  # true

# For raw post-quantum primitive (ML-KEM768):
bob = Sodium::KEM::MLKEM768::KeyPair.new
ciphertext, secret = Sodium::KEM::MLKEM768.encapsulate(bob.public_key)
# ...
```

### Secret Stream **[NEW]**

```crystal
key = Sodium::SecretStream.keygen
enc = Sodium::SecretStream::EncryptStream.new(key)
header = enc.header  # send/store this first

ciphertext1 = enc.push("Hello")
ciphertext2 = enc.push("World", tag: Sodium::SecretStream::Tag::Final)

# On the receiving side
dec = Sodium::SecretStream::DecryptStream.new(header, key)
message1, tag1 = dec.pull(ciphertext1)  # tag1 == Tag::Message
message2, tag2 = dec.pull(ciphertext2)  # tag2 == Tag::Final
```

### SHA-3 Hashing **[NEW]**

```crystal
digest256 = Sodium::Hash::SHA3_256.digest("data")
digest512 = Sodium::Hash::SHA3_512.digest("data")
```

### Extendable Output Functions (XOF) **[NEW]**

```crystal
# SHAKE128 (streaming)
shake = Sodium::XOF::Shake128.new
shake.update("Hello")
shake.update("World")
output = shake.final(64)  # 64 bytes of XOF output

# One-shot
output = Sodium::XOF::Shake128.digest("data", 32)

# TurboSHAKE128 with domain separation
output = Sodium::XOF::TurboShake128.digest("data", 32, domain: 0_u8)

# TurboSHAKE256
output = Sodium::XOF::TurboShake256.digest("data", 64, domain: 0x1f_u8)
```

### IP Address Encryption **[NEW]**

```crystal
key = Sodium::IPCrypt.keygen
encrypted = Sodium::IPCrypt.encrypt("192.168.1.1", key)
decrypted = Sodium::IPCrypt.decrypt(encrypted, key)
decrypted  # => "192.168.1.1"
```

### AEGIS AEAD **[NEW]**

```crystal
key = Random::Secure.random_bytes(Sodium::Cipher::Aegis128L::KEY_BYTES)
nonce = Random::Secure.random_bytes(Sodium::Cipher::Aegis128L::NPUB_BYTES)
ct = Sodium::Cipher::Aegis128L.encrypt("message", nonce, key)
dec = Sodium::Cipher::Aegis128L.decrypt(ct, nonce, key)

# AEGIS-256 works identically via Sodium::Cipher::Aegis256
```

### AES256-GCM AEAD **[NEW]**

```crystal
key = Random::Secure.random_bytes(Sodium::Cipher::Aes256Gcm::KEY_BYTES)
nonce = Random::Secure.random_bytes(Sodium::Cipher::Aes256Gcm::NPUB_BYTES)
ct = Sodium::Cipher::Aes256Gcm.encrypt("message", nonce, key)
dec = Sodium::Cipher::Aes256Gcm.decrypt(ct, nonce, key)
```

### ChaCha20-Poly1305 (original and IETF) **[NEW]**

```crystal
key = Random::Secure.random_bytes(Sodium::Cipher::Aead::ChaCha20Poly1305::KEY_SIZE)
nonce = Random::Secure.random_bytes(Sodium::Cipher::Aead::ChaCha20Poly1305::NONCE_SIZE)
ct = Sodium::Cipher::Aead::ChaCha20Poly1305.encrypt_static("message", nonce, key)
dec = Sodium::Cipher::Aead::ChaCha20Poly1305.decrypt_static(ct, nonce, key)
```

### SipHash **[NEW]**

```crystal
key = Random::Secure.random_bytes(Sodium::Hash::SipHash::KEY_BYTES)
hash = Sodium::Hash::SipHash.digest("message", key)
```

### Scrypt Password Hashing **[NEW]**

```crystal
scrypt = Sodium::Password::Scrypt.new
scrypt.ops = Sodium::Password::Scrypt::OPSLIMIT_INTERACTIVE
scrypt.mem = Sodium::Password::Scrypt::MEMLIMIT_INTERACTIVE

hash = scrypt.create_str("password")
scrypt.verify_str(hash, "password")  # => true
```

### One-Time Auth (Poly1305) **[NEW]**

```crystal
key = Random::Secure.random_bytes(Sodium::OneTimeAuth::KEY_BYTES)
tag = Sodium::OneTimeAuth.tag("message", key)
Sodium::OneTimeAuth.verify("message", tag, key)  # => true
```

### Padding **[NEW]**

```crystal
padded = Sodium::Padding.pad(data, block_size: 64)
original = Sodium::Padding.unpad(padded, block_size: 64)
```

### Helpers & Utilities **[NEW]**

```crystal
# Ed25519 → X25519 key conversion
x25519_pk = Sodium::Sign::Curve25519Convert.pk_to_curve25519(ed25519_pk)
x25519_sk = Sodium::Sign::Curve25519Convert.sk_to_curve25519(ed25519_sk)

# Extract seed / public key from Ed25519 secret key
seed = Sodium::Sign::KeyExtraction.sk_to_seed(secret_key)
pk   = Sodium::Sign::KeyExtraction.sk_to_pk(secret_key)

# Constant-time comparison
Sodium::ConstantTime.compare(a, b)   # => true/false
Sodium::ConstantTime.is_zero?(buf)    # => true/false

# Hex / Base64 encoding
hex = Sodium::Encoding.bin2hex(data)
data = Sodium::Encoding.hex2bin(hex)
b64 = Sodium::Encoding.bin2base64(data)
data = Sodium::Encoding.base642bin(b64)
```

---

Use `examples/pwhash_selector.cr` to help choose ops/mem limits.

Example output:
Ops limit →

|          | 1      | 4      | 16     | 64     | 256    | 1024   | 4096   | 16384  | 65536  | 262144 | 1048576 |
| -------- | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------- |
| 8K       |        |        |        |        |        |        |        |        |        | 0.542s | 2.114s  |
| 32K      |        |        |        |        |        |        |        |        | 0.513s | 2.069s |
| 128K     |        |        |        |        |        |        |        | 0.530s | 2.121s |
| 512K     |        |        |        |        |        |        | 0.566s | 2.237s |
| 2048K    |        |        |        |        |        | 0.567s | 2.290s |
| 8192K    |        |        |        |        | 0.670s | 2.542s |
| 32768K   |        |        |        | 0.684s | 2.777s |
| 131072K  |        |        | 0.805s | 3.106s |
| 524288K  | 0.504s | 1.135s | 3.661s |
| 2097152K | 2.119s |
| Memory   |

## Contributing

1. Fork it ( https://github.com/OkaVatti/sodium.cr/fork )
2. **Install a formatting check git hook (ln -sf ../../scripts/git/pre-commit .git/hooks)**
3. Create your feature branch (git checkout -b my-new-feature)
4. Commit your changes (git commit -am 'Add some feature')
5. Push to the branch (git push origin my-new-feature)
6. Create a new Pull Request

## Project History

- Originally created by [Andrew Hamon](https://github.com/andrewhamons/cox)
- Forked by [Didactic Drunk](https://github.com/didactic-drunk/cox) for lack of updates in the original project.
- Complaints about the name being too controversial. Project name changed from "cox" to a more libsodium related name of "salty seaman".
- ~50% complete libsodium API.
- More complaints about the name. Dead hooker jokes added.
- None of the original API is left.
- More complaints threatening a boycott. Told them "Go ahead, I own Coca Cola and Water".
- Account unsuspended.
- Unrelated to the boycott the project name changed to "libsodium" because sodium happens to be a tasty byproduct of the two earlier names.
- Account unsuspended.
- Dead hooker jokes (mostly) removed.
- **Forked by [OkaVatti](https://github.com/OkaVatti) in 2025/2026 after the upstream repository was considered to have been abandoned, having not received any updates in ~5 years.**
- This fork targets libsodium ≥ 1.0.22 and adds bindings for all APIs introduced between libsodium 1.0.18 and 1.0.22. See [Changes from upstream](#changes-from-upstream) below.

## Contributors

- [andrewhamon](https://github.com/andrewhamon) Andrew Hamon - creator, former maintainer
- [dorkrawk](https://github.com/dorkrawk) Dave Schwantes - contributor
- [didactic-drunk](https://github.com/didactic-drunk) - former maintainer
- [OkaVatti](https://github.com/OkaVatti) - current maintainer (for this fork)

---

## Changes from upstream

This fork incorporates the following additions and modifications relative to the original `didactic-drunk/sodium.cr`:

| Area                                  | Change                                                                                                                                                                                                                                         |
| :------------------------------------ | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **libsodium version**                 | Requires libsodium ≥ 1.0.22 (system installation). Original required libsodium ≥ 1.0.12.                                                                                                                                                       |
| **Key Exchange (KX)**                 | Added `Sodium::KX` with `Client` and `Server` classes. Supports seed-based deterministic key generation.                                                                                                                                       |
| **Sealed Boxes**                      | Added standalone `Sodium::SealedBox` class with `encrypt`/`decrypt` and `KeyPair` helper.                                                                                                                                                      |
| **Secret Stream**                     | Added `Sodium::SecretStream` with `EncryptStream`/`DecryptStream`, tag support, and rekeying.                                                                                                                                                  |
| **Post-Quantum KEM**                  | Added `Sodium::KEM` (X-Wing hybrid) and `Sodium::KEM::MLKEM768` (raw post-quantum).                                                                                                                                                            |
| **XOF (Extendable Output Functions)** | Added `Sodium::XOF::Shake128`, `Shake256`, `TurboShake128`, `TurboShake256` with streaming and one-shot APIs plus domain separation for TurboSHAKE.                                                                                            |
| **SHA-3 Hashing**                     | Added `Sodium::Hash::SHA3_256` and `SHA3_512` one-shot digest functions.                                                                                                                                                                       |
| **AEGIS AEADs**                       | Added `Sodium::Cipher::Aegis128L` and `Aegis256` static encrypt/decrypt methods.                                                                                                                                                               |
| **AES256-GCM**                        | Added `Sodium::Cipher::Aes256Gcm` with hardware detection and software fallback.                                                                                                                                                               |
| **ChaCha20-Poly1305 (original)**      | Added `Sodium::Cipher::Aead::ChaCha20Poly1305` with 8‑byte nonce.                                                                                                                                                                              |
| **ChaCha20-Poly1305-IETF**            | Added `Sodium::Cipher::Aead::ChaCha20Poly1305Ietf` with 12‑byte nonce.                                                                                                                                                                         |
| **IP Address Encryption**             | Added `Sodium::IPCrypt` with `encrypt`/`decrypt` and manual IP↔binary conversion (avoids a segfault in older libsodium `sodium_ip2bin`).                                                                                                       |
| **SecretBox detached mode**           | Added `encrypt_detached` and `decrypt_detached` methods.                                                                                                                                                                                       |
| **Pre-hashed Signatures**             | Added `Sodium::Sign::PreHashed` for Ed25519ph streaming sign/verify.                                                                                                                                                                           |
| **SipHash**                           | Added `Sodium::Hash::SipHash` fast keyed hash.                                                                                                                                                                                                 |
| **Scrypt**                            | Added `Sodium::Password::Scrypt` with key derivation and hash string support.                                                                                                                                                                  |
| **One-Time Auth (Poly1305)**          | Added `Sodium::OneTimeAuth` for single-use message authentication.                                                                                                                                                                             |
| **Padding**                           | Added `Sodium::Padding` for pad/unpad with block sizes.                                                                                                                                                                                        |
| **Helpers**                           | Added `Sodium::Sign::Curve25519Convert` (Ed25519↔X25519), `Sodium::Sign::KeyExtraction` (sk→pk, sk→seed), `Sodium::ConstantTime` (compare, is_zero?, increment, random), `Sodium::Encoding` (hex, base64), `Sodium::ScalarmultEd25519Noclamp`. |
| **Deprecation fixes**                 | Replaced deprecated `SecureBuffer.new`/`SecretKey.new` calls with `.copy_from`, `.move_from`, `.random` throughout.                                                                                                                            |
| **Test suite**                        | Expanded from ~60 to 104 specs. Added official test vectors for all new features where available.                                                                                                                                              |
| **`crypt` mode**                      | Password test vectors now handle `crypt` mode (modular crypt format) for Argon2 hashes.                                                                                                                                                        |
