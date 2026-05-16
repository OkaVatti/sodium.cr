# src/sodium/scalarmult_ed25519_noclamp.cr
require "../lib_sodium"
require "../secure_buffer"
require "../error"

module Sodium
  # Low‑level Ed25519 scalar multiplication **without clamping**.
  #
  # WARNING: These functions skip the clamping step that protects against
  # small‑subgroup attacks. They are intended for advanced protocols (e.g.,
  # VRFs, blind signatures) that require raw arithmetic on the curve.
  module ScalarmultEd25519Noclamp
    BYTES       = LibSodium.crypto_scalarmult_ed25519_bytes
    SCALARBYTES = LibSodium.crypto_scalarmult_ed25519_scalarbytes

    # Multiply the base point by a scalar `n` (no clamping).
    # Returns the Y coordinate of the resulting point.
    def self.base(n : Bytes) : Bytes
      q = Bytes.new(BYTES)
      if LibSodium.crypto_scalarmult_ed25519_base_noclamp(q, n) != 0
        raise Sodium::Error.new("crypto_scalarmult_ed25519_base_noclamp failed (scalar may be 0)")
      end
      q
    end

    # Multiply a point `p` by a scalar `n` (no clamping).
    # Returns the Y coordinate of the resulting point.
    def self.mult(n : Bytes, p : Bytes) : Bytes
      q = Bytes.new(BYTES)
      if LibSodium.crypto_scalarmult_ed25519_noclamp(q, n, p) != 0
        raise Sodium::Error.new("crypto_scalarmult_ed25519_noclamp failed (scalar may be 0 or point invalid)")
      end
      q
    end
  end
end
