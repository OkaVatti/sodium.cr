# spec/sodium/cipher/aegis_spec.cr
require "../../spec_helper"
require "../../../src/sodium/cipher/aegis"

describe Sodium::Cipher::Aegis128L do
  it "encrypts and decrypts" do
    key = Random::Secure.random_bytes(Sodium::Cipher::Aegis128L::KEY_BYTES)
    nonce = Random::Secure.random_bytes(Sodium::Cipher::Aegis128L::NPUB_BYTES)
    msg = "hello aegis"
    ct = Sodium::Cipher::Aegis128L.encrypt(msg, nonce, key)
    dec = Sodium::Cipher::Aegis128L.decrypt(ct, nonce, key)
    dec.should eq msg.to_slice
  end
end

describe Sodium::Cipher::Aegis256 do
  it "encrypts and decrypts" do
    key = Random::Secure.random_bytes(Sodium::Cipher::Aegis256::KEY_BYTES)
    nonce = Random::Secure.random_bytes(Sodium::Cipher::Aegis256::NPUB_BYTES)
    msg = "hello aegis256"
    ct = Sodium::Cipher::Aegis256.encrypt(msg, nonce, key)
    dec = Sodium::Cipher::Aegis256.decrypt(ct, nonce, key)
    dec.should eq msg.to_slice
  end
end
