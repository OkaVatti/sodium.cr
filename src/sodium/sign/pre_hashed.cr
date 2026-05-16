# src/sodium/sign/pre_hashed.cr
require "../lib_sodium"
require "../secure_buffer"
require "../error"
require "./secret_key"
require "./public_key"

module Sodium::Sign
  # Ed25519ph – pre‑hashed signing (message hashed with SHA‑512 internally).
  class PreHashed
    def initialize
      @state = uninitialized LibSodium::CryptoSignEd25519phState
      if LibSodium.crypto_sign_ed25519ph_init(pointerof(@state)) != 0
        raise Sodium::Error.new("crypto_sign_ed25519ph_init failed")
      end
    end

    # Feed a message chunk (can be called multiple times).
    def update(data : String | Bytes) : Nil
      d = data.is_a?(String) ? data.to_slice : data
      if LibSodium.crypto_sign_ed25519ph_update(pointerof(@state), d, d.bytesize) != 0
        raise Sodium::Error.new("crypto_sign_ed25519ph_update failed")
      end
    end

    # Finalize and produce a detached 64‑byte signature using the given secret key.
    def sign(secret_key : SecretKey) : Bytes
      sig = Bytes.new(SecretKey::SIG_SIZE)
      sig_len = uninitialized UInt64
      secret_key.key.readonly do |sk|
        if LibSodium.crypto_sign_ed25519ph_final_create(pointerof(@state), sig, pointerof(sig_len), sk) != 0
          raise Sodium::Error.new("crypto_sign_ed25519ph_final_create failed")
        end
      end
      raise "signature size mismatch" if sig_len != SecretKey::SIG_SIZE
      sig
    end

    # Finalize verification using a public key and the provided signature.
    # Raises `Error::VerificationFailed` on mismatch.
    def verify(signature : Bytes, public_key : PublicKey) : Nil
      pk = public_key.to_slice
      if LibSodium.crypto_sign_ed25519ph_final_verify(pointerof(@state), signature, pk) != 0
        raise Sodium::Error::VerificationFailed.new
      end
    end
  end
end
