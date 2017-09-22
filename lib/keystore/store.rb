require 'base64'
require 'openssl'

class Keystore
  # Keystore::Store provides the keystore storage methods used
  # to put encrypted data into DDB
  class Store
    def initialize(options)
      @options = options
    end

    def put_v1(key:, value:)
      # V1 encryption cannot handle empty strings without a special char
      value = "\0" if value.empty?
      key_id = @options[:key_id] || get_kms_keyid(@options[:key_alias])
      encrypted_value = @options[:kms]
                        .encrypt(key_id: key_id, plaintext: value)
                        .ciphertext_blob
      encoded_value = Base64.encode64(encrypted_value)
      @options[:dynamo].put_item(
        table_name: @options[:table_name],
        item: { ParameterName: key, Value: encoded_value }
      )
    end

    def split_keys(keystring)
      [keystring[0..31], keystring[32..-1]]
    end

    def encrypt_aes256(data_key:, plaintext: nil)
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
      cipher.update(plaintext) + cipher.final
    end

    def b64_utf8_encode(str)
      Base64.encode64(str).encode(Encoding::UTF_8)
    end

    def build_v2_row(params)
      unless (%i[key value version encryption_key hmac keystore_format] -
              params.keys).empty?
        raise 'Insufficient v2 row parameters'
      end
      # Attempt at credstash-compatible storage, setting ParameterName
      # as well as name attributes
      { ParameterName: params[:key], name: params[:key],
        version: params[:version],
        # Base64 encode then force into UTF-8 for safety in DDB
        key: b64_utf8_encode(params[:encryption_key]),
        contents: b64_utf8_encode(params[:value]),
        hmac: params[:hmac], keystore_format: params[:keystore_format] }
    end

    def generate_v2_keys(kms_key_id)
      # get encryption and HMAC keys from KMS (get 64 bytes from KMS, use
      # first half for encryption key, second half for HMAC key)
      kms_response = @options[:kms]
                     .generate_data_key(key_id: kms_key_id,
                                        number_of_bytes: 64)
      # the wrapped key (ciphertext_blob) is the encrypted version of the
      # encryption and hmac keys that contains information about the CMK
      # used to encrypt it. It is automatically decryptable by KMS API
      split_keys(kms_response.plaintext) + [kms_response.ciphertext_blob]
    end

    def encrypt_v2(plaintext)
      key_id = @options[:key_id] || get_kms_keyid(@options[:key_alias])

      data_key, hmac_key, wrapped_key = generate_v2_keys(key_id)
      ciphertext = encrypt_aes256(data_key: data_key, plaintext: plaintext)
      # Calculate HMAC for ciphertext with hmac_key
      b64_hmac = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'),
                                         hmac_key,
                                         ciphertext)
      [ciphertext, wrapped_key, b64_hmac]
    end

    def put_v2(key:, value: nil, version: 1)
      ciphertext, wrapped_key, b64_hmac = encrypt_v2(value)

      # Build the record structure to send to DDB
      data = build_v2_row(
        key: key, value: ciphertext, version: version,
        encryption_key: wrapped_key, hmac: b64_hmac, keystore_format: 'v2'
      )

      @options[:dynamo].put_item(
        table_name: @options[:table_name],
        item: data,
        # XXX: this condition expression is from credstash, but
        # it's not certain it will work with versioned keys
        condition_expression: 'attribute_not_exists(name)'
      )
    end
  end
end
