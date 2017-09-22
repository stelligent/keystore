#!/usr/bin/env ruby

require 'keystore'
require 'aws-sdk-core'
require 'trollop'

SUB_COMMANDS = %w[store retrieve].freeze
global_opts = Trollop.options do
  opt :region, 'The region to look for the dynamodb in', default: 'us-east-1'
  banner 'utility for storing and retrieving encrypted values
  available commands:

    store -- store a value in keystore
    retrieve -- retrieve a value from keystore

  use --help with either command for more information.
  '
  stop_on SUB_COMMANDS
end

cmd = ARGV.shift
cmd_opts =
  case cmd
  when 'store'
    Trollop.options do
      opt :value,
          'the value to be inserted into the keystore (required for store)',
          required: true, type: String
      opt :kmsid,
          'the kms key id to use to encrypt the data (conditionally ' \
          'required for store)',
          type: String
      opt :kmsalias,
          'the kms key alias to use to encrypt the data(conditionally ' \
          'required for store)', type: String
      opt :keyname, 'the name of the key associated with the value',
          required: true, type: String
      opt :table, 'the name of the table to perform the lookup on',
          required: true, type: String
    end
  when 'retrieve'
    Trollop.options do
      opt :keyname, 'the name of the key associated with the value',
          required: true, type: String
      opt :table, 'the name of the table to perform the lookup on',
          required: true, type: String
    end
  else
    Trollop.die 'usage: keystore.rb [store|retrieve] [parameters]'
  end

dynamo = Aws::DynamoDB::Client.new region: global_opts[:region]
kms = Aws::KMS::Client.new region: global_opts[:region]
keystore = Keystore.new dynamo: dynamo,
                        table_name: cmd_opts[:table],
                        kms: kms,
                        key_id: cmd_opts[:kmsid],
                        key_alias: cmd_opts[:kmsalias]

case cmd
when 'store'
  keystore.store key: cmd_opts[:keyname], value: cmd_opts[:value]
when 'retrieve'
  result = keystore.retrieve key: cmd_opts[:keyname]
  puts result
else
  raise "unknown subcommand #{cmd}"
end
