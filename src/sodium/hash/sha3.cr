# src/sodium/hash/sha3.cr
require "../lib_sodium"
require "../secure_buffer"
require "../error"

module Sodium
  module Hash
    # SHA‑3‑256 hashing.
    class SHA3_256
      BYTES = LibSodium.crypto_hash_sha3256_bytes.to_i

      def self.digest(data : String | Bytes) : Bytes
        message = data.is_a?(String) ? data.to_slice : data
        hash_out = Bytes.new(BYTES)
        if LibSodium.crypto_hash_sha3256(hash_out, message, message.bytesize) != 0
          raise Sodium::Error.new("SHA3‑256 hashing failed")
        end
        hash_out
      end
    end

    # SHA‑3‑512 hashing.
    class SHA3_512
      BYTES = LibSodium.crypto_hash_sha3512_bytes.to_i

      def self.digest(data : String | Bytes) : Bytes
        message = data.is_a?(String) ? data.to_slice : data
        hash_out = Bytes.new(BYTES)
        if LibSodium.crypto_hash_sha3512(hash_out, message, message.bytesize) != 0
          raise Sodium::Error.new("SHA3‑512 hashing failed")
        end
        hash_out
      end
    end
  end
end
