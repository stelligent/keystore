require 'aws-sdk-dynamodb'
require 'aws-sdk-kms'
require 'base64'

# rubocop:disable Metrics/AbcSize
class Keystore
  def initialize(params = {})
    @options = params
    raise 'need to specify dynamo parameter' if @options[:dynamo].nil?
    raise 'need to specify table_name parameter' if @options[:table_name].nil?
    raise 'need to specify kms parameter' if @options[:kms].nil?
  end

  def store(params)
    # only need key id to encrypt, so check for it here
    raise 'need to specify key_id or key_alias parameter' if @options[:key_id].nil? && @options[:key_alias].nil?

    key_id = @options[:key_id] || get_kms_keyid(@options[:key_alias])

    value_to_encrypt = params[:value].nil? || params[:value].empty? ? ' ' : params[:value]
    encrypted_value = @options[:kms].encrypt(key_id: key_id, plaintext: value_to_encrypt).ciphertext_blob
    encoded_value = Base64.encode64(encrypted_value)
    @options[:dynamo].put_item(
      table_name: @options[:table_name],
      item: { ParameterName: params[:key], Value: encoded_value }
    )
  end

  def retrieve(params)
    item = @options[:dynamo].get_item(table_name: @options[:table_name], key: { ParameterName: params[:key] }).item
    raise KeyNotFoundError.new, "keyname #{params[:key]} not found" if item.nil?
    raise KeyNotFoundError.new, "keyname #{params[:key]} not found" if item['Value'].nil?

    encoded_value = item['Value']
    encrypted_value = Base64.decode64(encoded_value)
    result = @options[:kms].decrypt(ciphertext_blob: encrypted_value).plaintext
    result.strip
  end

  private

  def get_kms_keyid(key_alias)
    @options[:kms].list_aliases.aliases.find { |resp| resp.alias_name == "alias/#{key_alias}" }.target_key_id
  rescue NoMethodError
    raise "#{key_alias} is not a valid kms key alias"
  end
end
# rubocop:enable Metrics/AbcSize

class KeyStoreError < StandardError
end

class KeyNotFoundError < KeyStoreError
end
