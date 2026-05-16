# spec/sodium/secret_stream_spec.cr
require "../spec_helper"

describe Sodium::SecretStream do
  it "encrypts and decrypts a stream" do
    key = Sodium::SecretStream.keygen

    # Encryption
    enc = Sodium::SecretStream::EncryptStream.new(key)
    header = enc.header

    c1 = enc.push("Hello")
    c2 = enc.push("World", tag: Sodium::SecretStream::Tag::Final)

    # Decryption
    dec = Sodium::SecretStream::DecryptStream.new(header, key)

    m1, t1 = dec.pull(c1)
    m2, t2 = dec.pull(c2)

    m1.should eq("Hello".to_slice)
    t1.should eq(Sodium::SecretStream::Tag::Message)
    m2.should eq("World".to_slice)
    t2.should eq(Sodium::SecretStream::Tag::Final)
  end

  it "detects tampered data" do
    key = Sodium::SecretStream.keygen
    enc = Sodium::SecretStream::EncryptStream.new(key)
    header = enc.header
    ciphertext = enc.push("Secret")

    # Tamper with the ciphertext
    ciphertext[0] ^= 0xFF

    dec = Sodium::SecretStream::DecryptStream.new(header, key)
    expect_raises(Sodium::Error) do
      dec.pull(ciphertext)
    end
  end

  it "handles rekeying" do
    key = Sodium::SecretStream.keygen

    enc = Sodium::SecretStream::EncryptStream.new(key)
    header = enc.header

    c1 = enc.push("First")
    enc.rekey
    c2 = enc.push("Second", tag: Sodium::SecretStream::Tag::Final)

    dec = Sodium::SecretStream::DecryptStream.new(header, key)

    m1, t1 = dec.pull(c1)
    dec.rekey # Must match encryption rekey point
    m2, t2 = dec.pull(c2)

    m1.should eq("First".to_slice)
    m2.should eq("Second".to_slice)
  end
end
