require 'aws-sdk-core'
begin
  require 'aws-sdk-dynamodb'
  require 'aws-sdk-kms'
rescue LoadError
  nil
end
require 'base64'
require 'openssl'

# utility to use AWS services to handle encryption and storage of secret data.
class Keystore
  def initialize(params = {})
    @options = params
    # Default to keystore storage format v1 (raw KMS encrypt of data in DDB, base64)
    @options[:keystore_format] ||= 'v1'
    # Default to creating default credential chain KMS and DDB clients in
    # us-east-1, if not passed dynamo/kms clients to use
    @options[:region] ||= 'us-east-1'
    # @options[:dynamo] ||= Aws::DynamoDB::Client.new(region: @options[:region])
    # @options[:kms] ||= Aws::KMS::Client.new(region: @options[:region])
    # Default to DDB table 'keystore-table' and KMS alias 'keystore' if
    # not otherwise specified
    @options[:table_name] ||= 'keystore-table'
    @options[:key_alias] ||= 'keystore' unless @options[:key_id]
  end

  def store(params)
    key_id = @options[:key_id] || get_kms_keyid(@options[:key_alias])

    secret = params[:value].nil? || params[:value].empty? ? ' ' : params[:value]

    # old version, encrypt data directly with KMS
    if @options[:keystore_format].eql? 'v1'
      encrypted_value = @options[:kms].encrypt(key_id: key_id, plaintext: secret).ciphertext_blob
      encoded_value = Base64.encode64(encrypted_value)
      return @options[:dynamo].put_item(
        table_name: @options[:table_name],
        item: { ParameterName: params[:key], Value: encoded_value }
      )
    end
    if @options[:keystore_format].eql? 'v2'
      # get encryption and HMAC keys from KMS (get 64 bytes from KMS, use
      # first half for encryption key, second half for HMAC key)
      kms_response = kms.generate_data_key(key_id: key_id, number_of_bytes: 64)
      data_key = kms_response.plaintext[0..31]
      hmac_key = kms_response.plaintext[32..-1]
      # the wrapped key (ciphertext_blob) is the encrypted version of the
      # encryption and hmac keys that contains information about the CMK
      # used to encrypt it. It is automatically decryptable by KMS API
      wrapped_key = kms_response.ciphertext_blob

      # Setup the AES-256-CTR cipher object with the data key provided
      # by KMS, and a random IV
      cipher = OpenSSL::Cipher.new('AES-256-CTR')
      cipher.encrypt
      cipher.key = data_key
      # NOTE: we use the implied iv of all-zeroes. This is not a crypto
      # weakness because data encryption keys are never reused for additional
      # data

      # Encrypt secret to obtain ciphertext (secret should be unused
      # after this point)
      ciphertext = cipher.update(secret) + cipher.final

      # Calculate HMAC for ciphertext with hmac_key
      b64_hmac = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'),
                                         hmac_key,
                                         ciphertext)

      # Build the record structure to send to DDB
      data = {}
      # Attempt at credstash-compatible storage, setting ParameterName
      # as well as name attributes
      data[:ParameterName] = data[:name] = params[:key]
      data[:version] = params[:version] ? params[:version] : '1'
      # Base64 encode then force into UTF-8 for safety in DDB
      data[:key] = Base64.encode64(wrapped_key).encode(Encoding::UTF_8)
      data[:contents] = Base64.encode(ciphertext).encode(Encoding::UTF_8)
      data[:hmac] = b64_hmac
      data[:keystore_format] = @options[:keystore_format]

      return @options[:dynamo].put_item(
        table_name: @options[:table_name],
        item: data,
        # XXX: this condition expression is from credstash, but
        # it's not certain it will work with versioned keys
        condition_expression: 'attribute_not_exists(name)'
      )
    end
    raise "Unknown keystore format: #{@options[:keystore_format]}"
  end

  def retrieve(params)
    # If we're given a key version to retrieve, we can assume v2+ format
    return retrieve_versioned(params).strip unless params[:version].nil?

    # No key version given, check if record exists for
    # ParameterName == params[:key], get a consistent return of the
    # single record with the highest version
    response = @options[:dynamo].query(limit: 1,
                                       table_name: @options[:table_name],
                                       key_condition_expression: \
                                       'ParameterName = :key',
                                       expression_attribute_values: {
                                         ':key' => params[:key]
                                       })
    if response.count.zero?
      # TODO: add retry logic for credstash stores
      raise KeyNotFoundError.new, "keyname #{params[:key]} not found"
    end
    item = response.items[0]
    # If no keystore_format or v1, assume v1 and do direct kms decrypt
    if item['keystore_format'].nil? || item['keystore_format'].eql?('v1')
      raise KeyNotFoundError.new, "keyname #{params[:key]} not found" \
        if item['Value'].nil?
      encoded_value = item['Value']
      encrypted_value = Base64.decode64(encoded_value)
      result = @options[:kms].decrypt(ciphertext_blob: encrypted_value).plaintext
      return result.strip
    end
    # If keystore format v2, do credstash-compatible decrypt
    return decrypt_v2_item(item) if item['keystore_format'].eql? 'v2'
    raise "Unknown keystore_format: #{item['keystore_format']}"
  end

  private

  # Decrypt a keystore format v2 ddb item
  def decrypt_v2_item(item)
    raise KeyNotFoundError, "No value for #{item['name']}\n" \
      if item['contents'].nil?
    material = item
    ciphertext = Base64.decode(material['contents'])
    # Decrypt envelope key
    kms_response = @options[:kms].decrypt(
      ciphertext_blob: Base64.decode(material['key'])
    )
    # Split envelope key into data and hmac keys
    data_key = kms_response.plaintext[0..31]
    hmac_key = kms_response.plaintext[32..-1]
    # Generate base64 HMAC of ciphertext for comparison
    b64_hmac = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'),
                                       hmac_key,
                                       ciphertext)
    # TODO: custom exception
    raise 'Integrity error, stored HMAC != computed HMAC' if \
      b64_hmac != material['hmac']

    # HMAC matches, data has not been tampered with
    cipher = OpenSSL::Cipher.new('AES-256-CTR')
    cipher.decrypt
    cipher.key = data_key
    # NOTE: we use the implied iv of all-zeroes. This is not a crypto
    # weakness because data encryption keys are never reused for additional
    # data
    secret = cipher.update(ciphertext)
    secret << cipher.final

    secret.strip
  end

  # Retrieve a versioned key
  def retrieve_versioned(params)
    response = @options[:dynamo].get_item(
      table_name: @options[:table_name],
      key: { 'ParameterName' => params[:key],
             'version' => params[:version] }
    )
    raise "Key #{params[:key]} not found" if response.item.nil? || !response.item
    item = response.item
    if item['keystore_format'] && item['keystore_format'].eql?('v2')
      return decrypt_v2_item(item)
    end
    raise "Unknown keystore_format: #{item['keystore_format']}"
  end

  def get_kms_keyid(key_alias)
    @options[:kms].list_aliases.aliases.find { |resp| resp.alias_name == "alias/#{key_alias}" }.target_key_id
  rescue NoMethodError
    raise "#{key_alias} is not a valid kms key alias"
  end
end

class KeyStoreError < StandardError
end

class KeyNotFoundError < KeyStoreError
end
