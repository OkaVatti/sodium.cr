require "../../spec_helper"
require "../../../src/sodium/password/scrypt"

describe Sodium::Password::Scrypt do
  it "derives a key from a password" do
    scrypt = Sodium::Password::Scrypt.new
    scrypt.ops = Sodium::Password::Scrypt::OPSLIMIT_INTERACTIVE
    scrypt.mem = Sodium::Password::Scrypt::MEMLIMIT_INTERACTIVE

    pass = "password"
    salt = Random::Secure.random_bytes(Sodium::Password::Scrypt::SALT_SIZE)
    key = scrypt.derive_key(pass, 32, salt)
    key.bytesize.should eq 32
    key.readonly do |k|
      k.should_not eq Bytes.new(32, 0_u8)
    end
  end

  it "creates and verifies a hash string" do
    scrypt = Sodium::Password::Scrypt.new
    scrypt.ops = Sodium::Password::Scrypt::OPSLIMIT_INTERACTIVE
    scrypt.mem = Sodium::Password::Scrypt::MEMLIMIT_INTERACTIVE

    pass = "secret"
    hash = scrypt.create_str(pass)
    scrypt.verify_str(hash, pass).should be_true
    scrypt.verify_str(hash, "wrong").should be_false
    scrypt.needs_rehash?(hash).should be_false
  end
end
