# src/sodium/sign/key_extraction.cr
require "../lib_sodium"
require "../secure_buffer"
require "../error"

module Sodium
  module Sign
    # Extract the seed or public key from an Ed25519 secret key.
    module KeyExtraction
      SEED_SIZE = LibSodium.crypto_sign_seedbytes
      PK_SIZE   = LibSodium.crypto_sign_publickeybytes

      # Extract the seed from an Ed25519 secret key.
      def self.sk_to_seed(secret_key : Bytes) : Bytes
        seed = Bytes.new(SEED_SIZE)
        if LibSodium.crypto_sign_ed25519_sk_to_seed(seed, secret_key) != 0
          raise Sodium::Error.new("crypto_sign_ed25519_sk_to_seed failed")
        end
        seed
      end

      # Extract the public key from an Ed25519 secret key.
      def self.sk_to_pk(secret_key : Bytes) : Bytes
        pk = Bytes.new(PK_SIZE)
        if LibSodium.crypto_sign_ed25519_sk_to_pk(pk, secret_key) != 0
          raise Sodium::Error.new("crypto_sign_ed25519_sk_to_pk failed")
        end
        pk
      end
    end
  end
end
