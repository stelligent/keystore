require 'keystore/cli'

describe Keystore::Cli do
  it 'initializes correctly' do
    cli_startopts = { region: 'us-east-1' }
    s = Keystore::Cli.new
    expect(s).to be_kind_of(Keystore::Cli)
    expect(s.instance_variable_get(:@opts)).to eq cli_startopts
  end
  describe 'Keystore::Cli.run' do
    it 'invokes v1 store correctly' do
      cli = Keystore::Cli.new
      dynamo = Aws::DynamoDB::Client.new region: 'us-east-1'
      kms = Aws::KMS::Client.new region: 'us-east-1'
      keystore = Keystore.new dynamo: dynamo,
                              table_name: 'notable',
                              kms: kms,
                              key_id: 'nokeyid',
                              key_alias: nil
      cli.instance_variable_set(:@keystore, keystore)
      def cli.init_clients; end
      expect(keystore).to(
        receive(:store).with(key: 'dummykey', value: 'dummyvalue')
      )
      def cli.argv
        %w[store -t notable -k nokeyid -e dummykey -v dummyvalue]
      end
      cli.run
    end
    it 'invokes v2 correctly' do
    end
    it 'defaults to us-east-1' do
    end
  end
end
