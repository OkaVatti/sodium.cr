# src/sodium/hash/siphash.cr
require "../lib_sodium"
require "../error"

module Sodium
  module Hash
    # SipHash‑2‑4 – fast, short‑input, keyed hash.
    class SipHash
      BYTES     = LibSodium.crypto_shorthash_siphash24_bytes.to_i
      KEY_BYTES = LibSodium.crypto_shorthash_siphash24_keybytes.to_i

      # Compute the 8‑byte SipHash of `data` under `key`.
      def self.digest(data : String | Bytes, key : Bytes) : Bytes
        msg = data.is_a?(String) ? data.to_slice : data
        raise ArgumentError.new("key must be #{KEY_BYTES} bytes") unless key.bytesize == KEY_BYTES
        hash_out = Bytes.new(BYTES)
        if LibSodium.crypto_shorthash_siphash24(hash_out, msg, msg.bytesize, key) != 0
          raise Sodium::Error.new("SipHash failed")
        end
        hash_out
      end
    end
  end
end
