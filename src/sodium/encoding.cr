# src/sodium/encoding.cr
require "./lib_sodium"
require "./error"

module Sodium
  # Constant‑time hexadecimal and Base64 encoding/decoding.
  module Encoding
    # --- Hexadecimal ---

    # Convert binary data to a hexadecimal string.
    def self.bin2hex(data : Bytes) : String
      hex_len = data.bytesize * 2 + 1
      hex = Bytes.new(hex_len)
      LibSodium.sodium_bin2hex(hex, hex_len, data, data.bytesize)
      String.new(hex.to_unsafe) # sodium_bin2hex always null‑terminates
    end

    # Convert a hexadecimal string to binary data.
    def self.hex2bin(hex : String) : Bytes
      bin_max = hex.bytesize // 2
      bin = Bytes.new(bin_max)
      bin_len = uninitialized LibC::SizeT
      if LibSodium.sodium_hex2bin(bin, bin_max, hex, hex.bytesize,
           nil, pointerof(bin_len), nil) != 0
        raise Sodium::Error.new("Invalid hexadecimal string")
      end
      bin[0, bin_len] # trim to actual length
    end

    # --- Base64 ---

    # Convert binary data to a Base64 string.
    # `variant` should be one of `SODIUM_BASE64_VARIANT_*` constants.
    def self.bin2base64(data : Bytes, variant : Int32 = LibSodium::SODIUM_BASE64_VARIANT_ORIGINAL) : String
      # sodium_bin2base64 computes the exact required length
      b64_len = LibSodium.sodium_base64_encoded_len(data.bytesize, variant)
      b64 = Bytes.new(b64_len)
      LibSodium.sodium_bin2base64(b64, b64_len, data, data.bytesize, variant)
      String.new(b64.to_unsafe)
    end

    # Convert a Base64 string to binary data.
    def self.base642bin(b64 : String, variant : Int32 = LibSodium::SODIUM_BASE64_VARIANT_ORIGINAL) : Bytes
      bin_max = b64.bytesize // 4 * 3 # upper bound
      bin = Bytes.new(bin_max)
      bin_len = uninitialized LibC::SizeT
      if LibSodium.sodium_base642bin(bin, bin_max, b64, b64.bytesize,
           nil, pointerof(bin_len), nil, variant) != 0
        raise Sodium::Error.new("Invalid Base64 string")
      end
      bin[0, bin_len]
    end
  end
end

# Helper to compute the encoded length of a Base64 string.
# Must be added to the `lib LibSodium` block:
#   fun sodium_base64_encoded_len(bin_len : LibC::SizeT, variant : LibC::Int) : LibC::SizeT
