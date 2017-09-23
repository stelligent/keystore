require 'keystore/cli'

describe Keystore::Cli do
  it 'initializes correctly' do
    s = Keystore::Cli.new
    expect(s).to be_kind_of(Keystore::Cli)
  end
end
