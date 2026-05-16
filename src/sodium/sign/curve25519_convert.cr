# src/sodium/sign/curve25519_convert.cr
require "../lib_sodium"
require "../secure_buffer"
require "../error"

module Sodium
  module Sign
    module Curve25519Convert
      def self.pk_to_curve25519(ed25519_pk : Bytes) : Bytes
        curve25519_pk = Bytes.new(LibSodium.crypto_box_publickeybytes.to_i32) # fixed
        if LibSodium.crypto_sign_ed25519_pk_to_curve25519(curve25519_pk, ed25519_pk) != 0
          raise Sodium::Error.new("crypto_sign_ed25519_pk_to_curve25519 failed")
        end
        curve25519_pk
      end

      def self.sk_to_curve25519(ed25519_sk : Bytes) : SecureBuffer
        curve25519_sk = SecureBuffer.new(LibSodium.crypto_box_secretkeybytes.to_i32) # fixed
        curve25519_sk.readwrite do |dst|
          if LibSodium.crypto_sign_ed25519_sk_to_curve25519(dst, ed25519_sk) != 0
            raise Sodium::Error.new("crypto_sign_ed25519_sk_to_curve25519 failed")
          end
        end
        curve25519_sk
      end
    end
  end
end
