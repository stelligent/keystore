require 'keystore'

# mock dynamo return value
class DDBResult
  attr_accessor :item
  def initialize(value)
    @item = { 'Value' => value }
  end
end

class DDBQueryOutput
  attr_accessor :count
  attr_accessor :items
  def initialize(items)
    @items = items.map(&:item)
    @count = items.length
  end
end

# mock KMS return value
class KMSResult
  attr_accessor :ciphertext_blob, :plaintext
  def initialize(value)
    @ciphertext_blob = value
    @plaintext = value
  end
end

describe 'Keystore' do
  context 'it can store encrypted values' do
    it 'will call DynamoDB to store the value' do
      mock_ddb = double('AWS::DynamoDB::Client')
      expect(mock_ddb).to receive(:put_item)

      mock_kms = double('AWS::KMS::Client')
      expect(mock_kms).to(
        receive(:encrypt).and_return(KMSResult.new('dontcare'))
      )

      keystore = Keystore.new dynamo: mock_ddb,
                              table_name: 'dontcare',
                              kms: mock_kms, key_id: 'dontcare',
                              key_alias: 'dontcare'

      begin
        keystore.store key: 'testkey', value: 'testvalue'
      rescue StandardError => e
        message = "Unexpected exception thrown: #{e}"
        raise message
      end
    end
  end

  context 'it can store empty values' do
    it 'will call KMS with an empty string to store the value' do
      mock_ddb = double('AWS::DynamoDB::Client')
      expect(mock_ddb).to receive(:put_item)

      mock_kms = double('AWS::KMS::Client')
      expect(mock_kms).to(
        receive(:encrypt).with(key_id: 'dontcare',
                               plaintext: "\0")
                                  .and_return(KMSResult.new('dontcare'))
      )

      keystore = Keystore.new dynamo: mock_ddb,
                              table_name: 'dontcare',
                              kms: mock_kms,
                              key_id: 'dontcare',
                              key_alias: 'dontcare'

      begin
        keystore.store key: 'testkey', value: ''
      rescue StandardError => e
        message = "Unexpected exception thrown: #{e}"
        raise message
      end
    end
  end

  context 'it can store nil values' do
    it 'will call KMS with an empty string to store the value' do
      mock_ddb = double('AWS::DynamoDB::Client')
      expect(mock_ddb).to receive(:put_item)

      mock_kms = double('AWS::KMS::Client')
      expect(mock_kms).to(
        receive(:encrypt).with(key_id: 'dontcare',
                               plaintext: "\0")
                         .and_return(KMSResult.new('dontcare'))
      )

      keystore = Keystore.new dynamo: mock_ddb, table_name: 'dontcare',
                              kms: mock_kms,
                              key_id: 'dontcare',
                              key_alias: 'dontcare'

      begin
        keystore.store key: 'testkey', value: ''
      rescue StandardError => e
        message = "Unexpected exception thrown: #{e}"
        raise message
      end
    end
  end

  context 'it can retrieve stored values' do
    it 'will return data for a given key' do
      mock_ddb = double('AWS::DynamoDB::Client')
      expect(mock_ddb).to receive(:query).and_return(
        DDBQueryOutput.new([DDBResult.new(Base64.encode64('dontcare'))])
      )

      mock_kms = double('AWS::KMS::Client')
      expect(mock_kms).to(
        receive(:decrypt).and_return(KMSResult.new('testvalue'))
      )

      keystore = Keystore.new dynamo: mock_ddb,
                              table_name: 'dontcare', kms: mock_kms

      begin
        result = keystore.retrieve key: 'testkey'
        expect(result).to be
        expect(result).to eq 'testvalue'
      rescue StandardError => e
        message = "Unexpected exception thrown: #{e}"
        raise message
      end
    end
  end

  context 'it can retrieve blank values' do
    it 'will return an empty string when it retrieves a nil or blank value' do
      mock_ddb = double('AWS::DynamoDB::Client')
      expect(mock_ddb).to receive(:query).and_return(
        DDBQueryOutput.new([DDBResult.new(Base64.encode64('dontcare'))])
      )

      mock_kms = double('AWS::KMS::Client')
      expect(mock_kms).to receive(:decrypt).and_return(KMSResult.new(' '))

      keystore = Keystore.new dynamo: mock_ddb,
                              table_name: 'dontcare',
                              kms: mock_kms

      begin
        result = keystore.retrieve key: 'testkey'
        expect(result).to be
        expect(result.empty?).to be true
        expect(result).to eq ''
      rescue StandardError => e
        message = "Unexpected exception thrown: #{e}"
        raise message
      end
    end
  end

  context 'it handles missing keys' do
    it 'will throw a specific error if the key does not exist' do
      mock_ddb = double('AWS::DynamoDB::Client')
      expect(mock_ddb).to receive(:query).and_return(
        DDBQueryOutput.new([DDBResult.new(nil)])
      )

      mock_kms = double('AWS::KMS::Client')

      keystore = Keystore.new dynamo: mock_ddb,
                              table_name: 'dontcare',
                              kms: mock_kms

      begin
        keystore.retrieve key: 'doesnotexist'
        raise 'Keystore did not throw exception on invalid key'
      rescue KeyNotFoundError => e
        # expected error
        puts e.message
      end
    end
  end
end
