# src/sodium/constant_time.cr
require "./lib_sodium"
require "./error"

module Sodium
  # Constant‑time comparison and zero‑testing utilities.
  module ConstantTime
    # Compare two byte sequences in constant time.
    # Returns `true` if they are identical, `false` otherwise.
    def self.compare(a : Bytes, b : Bytes) : Bool
      return false if a.bytesize != b.bytesize
      LibSodium.sodium_compare(a, b, a.bytesize) == 0
    end

    # Test whether a byte sequence is all zeros in constant time.
    def self.is_zero?(data : Bytes) : Bool
      LibSodium.sodium_is_zero(data, data.bytesize) == 1
    end

    # Increment a large unsigned number stored in little‑endian format.
    def self.increment(data : Bytes) : Nil
      LibSodium.sodium_increment(data, data.bytesize)
    end

    # Generate a random unsigned 32‑bit integer.
    def self.random_u32 : UInt32
      LibSodium.randombytes_random
    end

    # Generate a random unsigned 32‑bit integer in the range [0, upper_bound).
    def self.random_uniform(upper_bound : UInt32) : UInt32
      LibSodium.randombytes_uniform(upper_bound)
    end
  end
end
