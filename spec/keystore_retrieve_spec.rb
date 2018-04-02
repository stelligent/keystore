require 'keystore/retrieve'

describe Keystore::Retrieve do
  it 'initializes correctly' do
    s = Keystore::Retrieve.new({})
    expect(s).to be_kind_of(Keystore::Retrieve)
  end
end
