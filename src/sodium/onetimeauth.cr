# src/sodium/onetimeauth.cr
require "./lib_sodium"
require "./error"

module Sodium
  # Poly1305 one‑time authenticator.
  #
  # WARNING: The key must be used only once. Reusing a key with different messages
  # trivially breaks security. For a multi‑use MAC, prefer HMAC‑SHA‑2 or keyed BLAKE2b.
  class OneTimeAuth
    BYTES     = LibSodium.crypto_onetimeauth_poly1305_bytes.to_i
    KEY_BYTES = LibSodium.crypto_onetimeauth_poly1305_keybytes.to_i

    # Compute the 16‑byte Poly1305 MAC of `data` under `key`.
    def self.tag(data : String | Bytes, key : Bytes) : Bytes
      msg = data.is_a?(String) ? data.to_slice : data
      raise ArgumentError.new("key must be #{KEY_BYTES} bytes") unless key.bytesize == KEY_BYTES
      mac = Bytes.new(BYTES)
      if LibSodium.crypto_onetimeauth_poly1305(mac, msg, msg.bytesize, key) != 0
        raise Sodium::Error.new("Poly1305 tag failed")
      end
      mac
    end

    # Verify a Poly1305 tag for `data` under `key`.
    # Returns true if valid, false otherwise.
    def self.verify(data : String | Bytes, tag : Bytes, key : Bytes) : Bool
      msg = data.is_a?(String) ? data.to_slice : data
      raise ArgumentError.new("key must be #{KEY_BYTES} bytes") unless key.bytesize == KEY_BYTES
      raise ArgumentError.new("tag must be #{BYTES} bytes") unless tag.bytesize == BYTES
      LibSodium.crypto_onetimeauth_poly1305_verify(tag, msg, msg.bytesize, key) == 0
    end
  end
end
