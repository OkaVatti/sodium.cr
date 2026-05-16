require "../spec_helper"
require "../../src/sodium/kx"

describe Sodium::KX do
  it "generates shared secrets" do
    client = Sodium::KX::Client.new
    server = Sodium::KX::Server.new

    client_rx, client_tx = client.session_keys(server.public_key)
    server_rx, server_tx = server.session_keys(client.public_key)

    # Shared secrets are symmetric but swapped
    client_rx.should eq server_tx
    client_tx.should eq server_rx
    client_rx.should_not eq client_tx
  end
end
