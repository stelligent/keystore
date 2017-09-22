require 'aws-sdk-core'
begin
  require 'aws-sdk-dynamodb'
  require 'aws-sdk-kms'
rescue LoadError
  nil
end
require 'base64'
require 'openssl'
require 'keystore/store'

# utility to use AWS services to handle encryption and storage of secret data.
class Keystore
  def initialize(params = {})
    @options = {
      # Default to keystore storage format v1 (raw KMS encrypt of data in DDB,
      # base64)
      keystore_format: 'v1',
      # Default to creating default credential chain KMS and DDB clients in
      # us-east-1, if not passed dynamo/kms clients to use
      region: 'us-east-1',
      # Default to DDB table 'keystore-table'
      table_name: 'keystore-table'
    }.merge params

    # Default to KMS alias 'keystore' if not otherwise specified
    @options[:key_alias] ||= 'keystore' unless @options[:key_id]
  end

  def store(params)
    store = Keystore::Store.new(@options)
    case @options[:keystore_format]
    when 'v1'
      # old version, encrypt data directly with KMS
      store.put_v1(**params)
    when 'v2'
      store.put_v2(params[:value])
    else
      raise "Unknown keystore format: #{@options[:keystore_format]}"
    end
  end

  def retrieve(params)
    retrieve = Keystore::Retrieve.new(@options)
    retrieve.get(params)
  end

  private

  def get_kms_keyid(key_alias)
    @options[:kms].list_aliases.aliases.find do |resp|
      resp.alias_name == "alias/#{key_alias}"
    end.target_key_id
  rescue NoMethodError
    raise "#{key_alias} is not a valid kms key alias"
  end
end

class KeyStoreError < StandardError
end

class KeyNotFoundError < KeyStoreError
end
