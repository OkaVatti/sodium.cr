# src/sodium/sealed_box.cr
require "./lib_sodium"
require "./secure_buffer"
require "./error"

module Sodium
  # Provides anonymous public-key encryption (sealed boxes).
  #
  # Usage:
  #   recipient = SealedBox::KeyPair.new
  #   sealed   = SealedBox.encrypt("Hello!", recipient.public_key)
  #   message  = SealedBox.decrypt(sealed, recipient.public_key, recipient.secret_key)
  class SealedBox
    SEAL_BYTES = LibSodium.crypto_box_sealbytes.to_i

    # Encrypt a message for a recipient given their public key.
    # Returns the ciphertext (includes the ephemeral public key).
    def self.encrypt(message : String, public_key : Bytes) : Bytes
      encrypt(message.to_slice, public_key)
    end

    def self.encrypt(message : Bytes, public_key : Bytes) : Bytes
      dst = Bytes.new(message.bytesize + SEAL_BYTES)
      if LibSodium.crypto_box_seal(dst, message, message.bytesize, public_key) != 0
        raise Sodium::Error.new("crypto_box_seal failed")
      end
      dst
    end

    # Decrypt a sealed box.
    # Requires the recipient's key pair.
    def self.decrypt(ciphertext : Bytes, public_key : Bytes, secret_key : SecureBuffer) : Bytes
      dst_size = ciphertext.bytesize - SEAL_BYTES
      raise ArgumentError.new("Ciphertext too short") if dst_size <= 0
      dst = Bytes.new(dst_size)
      secret_key.readonly do |sk|
        if LibSodium.crypto_box_seal_open(dst, ciphertext, ciphertext.bytesize, public_key, sk) != 0
          raise Sodium::Error::DecryptionFailed.new("crypto_box_seal_open failed")
        end
      end
      dst
    end

    # Convenience class to generate and hold a key pair for sealed boxes.
    # These keys are identical to those used by CryptoBox.
    class KeyPair
      getter public_key : Bytes
      getter secret_key : SecureBuffer

      def initialize
        @public_key = Bytes.new(LibSodium.crypto_box_publickeybytes.to_i)
        @secret_key = SecureBuffer.new(LibSodium.crypto_box_secretkeybytes.to_i)
        secret_key.readwrite do |sk|
          if LibSodium.crypto_box_keypair(public_key, sk) != 0
            raise Sodium::Error.new("crypto_box_keypair failed")
          end
        end
      end

      # Initialize from an existing key pair.
      def initialize(@public_key : Bytes, @secret_key : SecureBuffer)
        raise ArgumentError.new("Invalid public key size") unless public_key.bytesize == LibSodium.crypto_box_publickeybytes
        raise ArgumentError.new("Invalid secret key size") unless secret_key.bytesize == LibSodium.crypto_box_secretkeybytes
      end
    end
  end
end
