# src/sodium/ipcrypt.cr
require "./lib_sodium"
require "./secure_buffer"
require "./error"
require "socket"

module Sodium
  module IPCrypt
    KEY_BYTES = LibSodium.crypto_ipcrypt_keybytes.to_i

    def self.keygen : SecureBuffer
      buf = SecureBuffer.new(KEY_BYTES)
      buf.readwrite do |slice|
        LibSodium.randombytes_buf(slice, KEY_BYTES)
      end
      buf
    end

    # Encrypt an IP address (IPv4 or IPv6) into a binary buffer.
    def self.encrypt(address : String, key : Bytes | SecureBuffer) : Bytes
      ip_bin = ip_to_bin(address)
      dst = Bytes.new(16) # always 16 bytes for both families
      key_ptr = key.is_a?(SecureBuffer) ? key.to_unsafe : key
      LibSodium.crypto_ipcrypt_encrypt(dst, ip_bin, key_ptr)
      dst
    end

    # Decrypt a binary encrypted IP address back to a string.
    def self.decrypt(encrypted_ip : Bytes, key : Bytes | SecureBuffer) : String
      dst = Bytes.new(16)
      key_ptr = key.is_a?(SecureBuffer) ? key.to_unsafe : key
      if LibSodium.crypto_ipcrypt_decrypt(dst, encrypted_ip, key_ptr) != 0
        raise Sodium::Error.new("IP address decryption failed")
      end
      bin_to_ip(dst)
    end

    # --- Pure‑Crystal IPv4 / IPv6 ↔ binary conversion ---

    private def self.ip_to_bin(ip : String) : Bytes
      if ip.includes?(':')
        parse_ipv6(ip)
      else
        parse_ipv4(ip)
      end
    end

    private def self.bin_to_ip(bin : Bytes) : String
      # IPv4‑mapped IPv6 detection (first 10 bytes zero, then 0xFF 0xFF)
      if bin[0, 10].all?(&.zero?) && bin[10] == 0xff_u8 && bin[11] == 0xff_u8
        "#{bin[12]}.#{bin[13]}.#{bin[14]}.#{bin[15]}"
      else
        format_ipv6(bin)
      end
    end

    # --- IPv4 helpers ---

    private def self.parse_ipv4(ip : String) : Bytes
      parts = ip.split('.')
      raise ArgumentError.new("Invalid IPv4 address: #{ip}") if parts.size != 4
      octets = parts.map do |p|
        val = p.to_u8? || raise(ArgumentError.new("Invalid IPv4 octet: #{p}"))
        val
      end
      bin = Bytes.new(16, 0_u8)
      bin[10] = 0xff_u8
      bin[11] = 0xff_u8
      bin[12] = octets[0]
      bin[13] = octets[1]
      bin[14] = octets[2]
      bin[15] = octets[3]
      bin
    end

    # --- IPv6 helpers ---

    private def self.parse_ipv6(ip : String) : Bytes
      # Expand `::` shorthand
      if ip.includes?("::")
        left, right = ip.split("::", 2)
        left_parts = left.empty? ? [] of String : left.split(':')
        right_parts = right.empty? ? [] of String : right.split(':')
        missing = 8 - left_parts.size - right_parts.size
        parts = left_parts + (["0"] * missing) + right_parts
      else
        parts = ip.split(':')
      end

      raise ArgumentError.new("Invalid IPv6 address: #{ip}") if parts.size != 8

      bin = Bytes.new(16)
      parts.each_with_index do |part, i|
        val = part.to_u16?(base: 16) || raise(ArgumentError.new("Invalid IPv6 segment: #{part}"))
        bin[2 * i] = (val >> 8).to_u8
        bin[2 * i + 1] = (val & 0xFF).to_u8
      end
      bin
    end

    private def self.format_ipv6(bin : Bytes) : String
      groups = (0..7).map do |i|
        hi = bin[2 * i].to_u16 << 8
        lo = bin[2 * i + 1].to_u16
        (hi | lo).to_s(16)
      end
      groups.join(':')
    end
  end
end
