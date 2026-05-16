# src/sodium/padding.cr
require "./lib_sodium"
require "./error"

module Sodium
  module Padding
    # Pad `data` to a multiple of `block_size`.
    def self.pad(data : Bytes, block_size : Int) : Bytes
      maxlen = data.bytesize.to_u64 + block_size.to_u64
      buf = Bytes.new(maxlen.to_i)
      data.copy_to(buf)
      padded_len = uninitialized LibC::SizeT
      if LibSodium.sodium_pad(pointerof(padded_len), buf, data.bytesize.to_u64, block_size.to_u64, maxlen) != 0
        raise Sodium::Error.new("sodium_pad failed")
      end
      buf[0, padded_len.to_i]
    end

    # Remove padding from `data`, returning the original message.
    def self.unpad(padded : Bytes, block_size : Int) : Bytes
      buf = padded.dup
      unpadded_len = uninitialized LibC::SizeT
      if LibSodium.sodium_unpad(pointerof(unpadded_len), buf, padded.bytesize.to_u64, block_size.to_u64) != 0
        raise Sodium::Error.new("sodium_unpad failed (corrupted padding)")
      end
      buf[0, unpadded_len.to_i]
    end
  end
end
