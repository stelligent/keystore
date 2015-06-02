require 'aws-sdk-core'
require 'base64'

# utility to use AWS services to handle encryption and storage of secret data.
class Keystore
  def initialize(params = {})
    @options = params
    fail 'need to specify dynamo parameter' if @options[:dynamo].nil?
    fail 'need to specify table_name parameter' if @options[:table_name].nil?
    fail 'need to specify kms parameter' if @options[:kms].nil?
  end

  def store(params)
    # only need key id to encrypt, so check for it here
    fail 'need to specify key_id parameter' if @options[:key_id].nil?
    key_id = @options[:key_id]
    encrypted_value = @options[:kms].encrypt(key_id: key_id, plaintext: params[:value]).ciphertext_blob
    encoded_value = Base64.encode64(encrypted_value)
    @options[:dynamo].put_item(
      table_name: @options[:table_name],
      item: { ParameterName: params[:key], Value: encoded_value }
    )
  end

  def retrieve(params)
    item = @options[:dynamo].get_item(table_name: @options[:table_name], key: { ParameterName: params[:key] }).item
    encoded_value = item['Value']
    encrypted_value = Base64.decode64(encoded_value)
    @options[:kms].decrypt(ciphertext_blob: encrypted_value).plaintext
  end
end
