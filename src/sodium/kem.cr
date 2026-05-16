# src/sodium/kem.cr
require "./lib_sodium"
require "./secure_buffer"
require "./error"

module Sodium
  # Implements libsodium's crypto_kem API for Post-Quantum Key Encapsulation.
  #
  # By default, the KEM module uses X-Wing, a hybrid KEM that combines the
  # NIST-standardized ML-KEM768 with X25519 for defense against both classical
  # and quantum adversaries. This is the recommended choice for most applications.
  #
  # For raw post-quantum primitives, the MLKEM768 module is also available.
  #
  # Usage:
  #   # Sender
  #   recipient_key = KEM::PublicKey.new(some_bytes)
  #   ciphertext, shared_secret = KEM.encapsulate(recipient_key)
  #
  #   # Recipient
  #   keypair = KEM::KeyPair.new
  #   shared_secret = KEM.decapsulate(ciphertext, keypair)
  #
  # Note: Unlike KX (Key Exchange), KEM is asymmetric: only the recipient
  # needs a long-term key pair. The sender creates a shared secret using
  # only the recipient's public key.
  module KEM
    # --- High-Level X-Wing (Recommended) ---
    PUBLIC_KEY_BYTES    = LibSodium.crypto_kem_publickeybytes.to_i
    SECRET_KEY_BYTES    = LibSodium.crypto_kem_secretkeybytes.to_i
    CIPHERTEXT_BYTES    = LibSodium.crypto_kem_ciphertextbytes.to_i
    SHARED_SECRET_BYTES = LibSodium.crypto_kem_sharedsecretbytes.to_i
    SEED_BYTES          = LibSodium.crypto_kem_seedbytes.to_i

    # Encapsulate a shared secret for the given recipient public key.
    # Returns a tuple of {ciphertext, shared_secret}.
    # The ciphertext must be sent to the recipient, who can decapsulate it.
    def self.encapsulate(public_key : Bytes) : {Bytes, Bytes}
      ct = Bytes.new(CIPHERTEXT_BYTES)
      ss = Bytes.new(SHARED_SECRET_BYTES)
      if LibSodium.crypto_kem_enc(ct, ss, public_key) != 0
        raise Sodium::Error.new("crypto_kem_enc failed")
      end
      {ct, ss}
    end

    # Decapsulate a ciphertext to recover the shared secret.
    # Requires the recipient's key pair.
    def self.decapsulate(ciphertext : Bytes, keypair : KeyPair) : Bytes
      ss = Bytes.new(SHARED_SECRET_BYTES)
      keypair.secret_key.readonly do |sk|
        if LibSodium.crypto_kem_dec(ss, ciphertext, sk) != 0
          raise Sodium::Error.new("crypto_kem_dec failed")
        end
      end
      ss
    end

    # Holds a KEM key pair.
    class KeyPair
      getter public_key : Bytes
      getter secret_key : SecureBuffer

      def initialize
        @public_key = Bytes.new(PUBLIC_KEY_BYTES)
        @secret_key = SecureBuffer.new(SECRET_KEY_BYTES)
        secret_key.readwrite do |sk|
          if LibSodium.crypto_kem_keypair(public_key, sk) != 0
            raise Sodium::Error.new("crypto_kem_keypair failed")
          end
        end
      end

      def initialize(seed : Bytes)
        raise ArgumentError.new("Seed must be #{SEED_BYTES} bytes") unless seed.bytesize == SEED_BYTES
        @public_key = Bytes.new(PUBLIC_KEY_BYTES)
        @secret_key = SecureBuffer.new(SECRET_KEY_BYTES)
        secret_key.readwrite do |sk|
          if LibSodium.crypto_kem_seed_keypair(public_key, sk, seed) != 0
            raise Sodium::Error.new("crypto_kem_seed_keypair failed")
          end
        end
      end

      def initialize(@public_key : Bytes, @secret_key : SecureBuffer)
        raise ArgumentError.new("Invalid public key size") unless public_key.bytesize == PUBLIC_KEY_BYTES
        raise ArgumentError.new("Invalid secret key size") unless secret_key.bytesize == SECRET_KEY_BYTES
      end
    end

    # --- Low-Level ML-KEM768 ---
    # This provides the raw post-quantum primitive without the classical X25519
    # hybrid. It should only be used when interoperability with other ML-KEM
    # implementations is specifically required.
    module MLKEM768
      PUBLIC_KEY_BYTES    = LibSodium.crypto_kem_mlkem768_publickeybytes.to_i
      SECRET_KEY_BYTES    = LibSodium.crypto_kem_mlkem768_secretkeybytes.to_i
      CIPHERTEXT_BYTES    = LibSodium.crypto_kem_mlkem768_ciphertextbytes.to_i
      SHARED_SECRET_BYTES = LibSodium.crypto_kem_mlkem768_sharedsecretbytes.to_i
      SEED_BYTES          = LibSodium.crypto_kem_mlkem768_seedbytes.to_i

      def self.encapsulate(public_key : Bytes) : {Bytes, Bytes}
        ct = Bytes.new(CIPHERTEXT_BYTES)
        ss = Bytes.new(SHARED_SECRET_BYTES)
        if LibSodium.crypto_kem_mlkem768_enc(ct, ss, public_key) != 0
          raise Sodium::Error.new("crypto_kem_mlkem768_enc failed")
        end
        {ct, ss}
      end

      def self.decapsulate(ciphertext : Bytes, keypair : KeyPair) : Bytes
        ss = Bytes.new(SHARED_SECRET_BYTES)
        keypair.secret_key.readonly do |sk|
          if LibSodium.crypto_kem_mlkem768_dec(ss, ciphertext, sk) != 0
            raise Sodium::Error.new("crypto_kem_mlkem768_dec failed")
          end
        end
        ss
      end

      class KeyPair
        getter public_key : Bytes
        getter secret_key : SecureBuffer

        def initialize
          @public_key = Bytes.new(PUBLIC_KEY_BYTES)
          @secret_key = SecureBuffer.new(SECRET_KEY_BYTES)
          secret_key.readwrite do |sk|
            if LibSodium.crypto_kem_mlkem768_keypair(public_key, sk) != 0
              raise Sodium::Error.new("crypto_kem_mlkem768_keypair failed")
            end
          end
        end

        def initialize(seed : Bytes)
          raise ArgumentError.new("Seed must be #{SEED_BYTES} bytes") unless seed.bytesize == SEED_BYTES
          @public_key = Bytes.new(PUBLIC_KEY_BYTES)
          @secret_key = SecureBuffer.new(SECRET_KEY_BYTES)
          secret_key.readwrite do |sk|
            if LibSodium.crypto_kem_mlkem768_seed_keypair(public_key, sk, seed) != 0
              raise Sodium::Error.new("crypto_kem_mlkem768_seed_keypair failed")
            end
          end
        end

        def initialize(@public_key : Bytes, @secret_key : SecureBuffer)
          raise ArgumentError.new("Invalid public key size") unless public_key.bytesize == PUBLIC_KEY_BYTES
          raise ArgumentError.new("Invalid secret key size") unless secret_key.bytesize == SECRET_KEY_BYTES
        end
      end
    end
  end
end
