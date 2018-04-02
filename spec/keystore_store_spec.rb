require 'keystore/store'

describe Keystore::Store do
  it 'initializes correctly' do
    s = Keystore::Store.new({})
    expect(s).to be_kind_of(Keystore::Store)
  end
end
