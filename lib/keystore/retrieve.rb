class Keystore
  # Keystore::Retrieve provides the keystore retrieval methods used
  # to pull encrypted data from DDB
  class Retrieve
    def initialize(options)
      @options = options
    end

    def retrieve_ddb_row(params)
      kce = 'ParameterName = :key'
      eav = { ':key' => params[:key] }
      if params[:version]
        kce += ' AND version = :version'
        eav[':version'] = params[:version]
      end

      @options[:dynamo].query(
        limit: 1,
        table_name: @options[:table_name],
        key_condition_expression: kce,
        expression_attribute_values: eav
      )
    end

    def get(params)
      response = retrieve_ddb_row(params)
      if response.count.zero?
        # TODO: add retry logic for credstash stores
        raise KeyNotFoundError.new, "keyname #{params[:key]} not found"
      end
      item = response.items[0]
      # If no keystore_format or v1, assume v1 and do direct kms decrypt
      case item['keystore_format']
      when nil, 'v1'
        raise KeyNotFoundError.new, "keyname #{params[:key]} not found" \
          if item['Value'].nil?
        encoded_value = item['Value']
        encrypted_value = Base64.decode64(encoded_value)
        result = @options[:kms].decrypt(ciphertext_blob: encrypted_value)
                               .plaintext
        return result.strip
      when 'v2'
        # If keystore format v2, do credstash-compatible decrypt
        return decrypt_v2_item(item)
      else
        raise "Unknown keystore_format: #{item['keystore_format']}"
      end
    end

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
      item = @options[:dynamo].get_item(
        table_name: @options[:table_name],
        key: { 'ParameterName' => params[:key],
               'version' => params[:version] }
      ).item
      raise "Key #{params[:key]} not found" if item.nil? || !item

      if item['keystore_format'] && item['keystore_format'].eql?('v2')
        return decrypt_v2_item(item)
      end
      raise "Unknown keystore_format: #{item['keystore_format']}"
    end
  end
end
