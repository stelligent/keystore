require 'aws-sdk-core'
require 'base64'

class Keystore

  def initialize params = {} 
    @options = params
    raise "need to specify dynamo parameter" if @options[:dynamo].nil?
    raise "need to specify table_name parameter" if @options[:table_name].nil? 
    raise "need to specify kms parameter" if @options[:kms].nil? 
  end

  def store params 
    encrypted_value = @options[:kms].encrypt(key_id: "55a683c6-2f44-42a4-a7c3-1e893c80b6df", plaintext: params[:value]).ciphertext_blob
    encoded_value = Base64.encode64(encrypted_value)
    @options[:dynamo].put_item(:table_name => @options[:table_name], item: { "ParameterName" => params[:key], "Value" => encoded_value })
  end

  def retrieve params
    item = @options[:dynamo].get_item(table_name: @options[:table_name], key: { 'ParameterName' => params[:key] } ).item
    encoded_value = item["Value"]
    encrypted_value = Base64.decode64(encoded_value)
    result = @options[:kms].decrypt(ciphertext_blob: encrypted_value).plaintext
  end
end
