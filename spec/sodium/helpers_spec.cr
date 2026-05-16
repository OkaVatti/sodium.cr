# spec/sodium/helpers_spec.cr
require "../spec_helper"
require "../../src/sodium/sign/public_key"
require "../../src/sodium/sign/secret_key"
require "../../src/sodium/sign/key_extraction"
require "../../src/sodium/sign/curve25519_convert"

describe "Helper Functions" do
  it "extracts seed from secret key" do
    key = Sodium::Sign::SecretKey.random
    seed = key.key.readonly { |slice| Sodium::Sign::KeyExtraction.sk_to_seed(slice) }
    seed.bytesize.should eq(Sodium::Sign::KeyExtraction::SEED_SIZE)
  end

  it "extracts public key from secret key" do
    key = Sodium::Sign::SecretKey.random
    pk = key.key.readonly { |slice| Sodium::Sign::KeyExtraction.sk_to_pk(slice) }
    pk.bytesize.should eq(Sodium::Sign::KeyExtraction::PK_SIZE)
  end

  it "converts Ed25519 keys to Curve25519" do
    sign_key = Sodium::Sign::SecretKey.random
    box_pk = Sodium::Sign::Curve25519Convert.pk_to_curve25519(sign_key.public_key.to_slice)
    box_sk = sign_key.key.readonly { |slice| Sodium::Sign::Curve25519Convert.sk_to_curve25519(slice) }
    box_pk.bytesize.should eq(Sodium::CryptoBox::PublicKey::KEY_SIZE)
  end

  it "hex encoding round-trips" do
    data = Random::Secure.random_bytes(32)
    hex = Sodium::Encoding.bin2hex(data)
    Sodium::Encoding.hex2bin(hex).should eq(data)
  end

  it "constant-time comparison works" do
    a = Bytes[1, 2, 3]
    b = Bytes[1, 2, 3]
    Sodium::ConstantTime.compare(a, b).should be_true
    Sodium::ConstantTime.compare(a, Bytes[1, 2, 4]).should be_false
  end
end
