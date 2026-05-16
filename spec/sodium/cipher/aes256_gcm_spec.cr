# spec/sodium/cipher/aes256_gcm_spec.cr
require "../../spec_helper"
require "../../../src/sodium/cipher/aes256_gcm"

describe Sodium::Cipher::Aes256Gcm do
  if Sodium::Cipher::Aes256Gcm.available?
    it "encrypts and decrypts correctly" do
      key = Random::Secure.random_bytes(Sodium::Cipher::Aes256Gcm::KEY_BYTES)
      nonce = Random::Secure.random_bytes(Sodium::Cipher::Aes256Gcm::NPUB_BYTES)
      message = "Hello AES-GCM"
      ad = "extra data".to_slice

      ct = Sodium::Cipher::Aes256Gcm.encrypt(message, nonce, key, additional_data: ad)
      dec = Sodium::Cipher::Aes256Gcm.decrypt(ct, nonce, key, additional_data: ad)
      dec.should eq message.to_slice
    end

    it "fails on tampered ciphertext" do
      key = Random::Secure.random_bytes(Sodium::Cipher::Aes256Gcm::KEY_BYTES)
      nonce = Random::Secure.random_bytes(Sodium::Cipher::Aes256Gcm::NPUB_BYTES)
      ct = Sodium::Cipher::Aes256Gcm.encrypt("msg", nonce, key)
      ct[0] ^= 0xFF
      expect_raises(Sodium::Error) do
        Sodium::Cipher::Aes256Gcm.decrypt(ct, nonce, key)
      end
    end
  else
    pending "AES256-GCM is not available on this CPU"
  end
end
