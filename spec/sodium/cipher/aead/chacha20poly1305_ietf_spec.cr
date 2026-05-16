require "../../../spec_helper"
require "../../../../src/sodium/cipher/aead/chalsa"

describe Sodium::Cipher::Aead::ChaCha20Poly1305Ietf do
  it "encrypts/decrypts a message" do
    key = Random::Secure.random_bytes(Sodium::Cipher::Aead::ChaCha20Poly1305Ietf::KEY_SIZE)
    nonce = Random::Secure.random_bytes(Sodium::Cipher::Aead::ChaCha20Poly1305Ietf::NONCE_SIZE)
    message = "test"
    ct = Sodium::Cipher::Aead::ChaCha20Poly1305Ietf.encrypt_static(message, nonce, key)
    dec = Sodium::Cipher::Aead::ChaCha20Poly1305Ietf.decrypt_static(ct, nonce, key)
    dec.should eq message.to_slice
  end

  it "deterministically encrypts and decrypts with known key/nonce" do
    key = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f".hexbytes
    nonce = "070000004041424344454647".hexbytes # 12 bytes
    plaintext = "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e".hexbytes
    ad = "50515253c0c1c2c3c4c5c6c7".hexbytes

    ct = Sodium::Cipher::Aead::ChaCha20Poly1305Ietf.encrypt_static(plaintext, nonce, key, additional: ad)
    dec = Sodium::Cipher::Aead::ChaCha20Poly1305Ietf.decrypt_static(ct, nonce, key, additional: ad)
    dec.should eq plaintext
  end
end
