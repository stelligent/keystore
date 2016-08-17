require 'aws-sdk-core'
require 'keystore'

timestamp = Time.now.strftime '%Y%m%d%H%M%S'
ts_key = "testkey#{timestamp}"
ts_val = "testvalue#{timestamp}"

Given(/^test data to use$/) do
  @key = ts_key
  @value = ts_val
end

Given(/^a region to operate in$/) do
  @region = ENV['region']
  raise if @region.nil?
end

Given(/^a KMS key id or KMS key alias to use$/) do
  @key_id = ENV['key_id']
  @key_alias = ENV['key_alias']
  raise if @key_id.nil? && @key_alias.nil?
end

Given(/^a DynamoDB table to use$/) do
  @table_name = ENV['table_name']
  raise if @table_name.nil?
end

When(/^I store a value in the keystore$/) do
  @dynamo = Aws::DynamoDB::Client.new region: @region
  @kms = Aws::KMS::Client.new region: @region
  keystore = Keystore.new dynamo: @dynamo, table_name: @table_name, kms: @kms, key_id: @key_id, key_alias: @key_alias
  keystore.store key: @key, value: @value
end

Then(/^I should see that encrypted data in the raw data store$/) do
  name = { 'ParameterName' => @key }
  @result = @dynamo.get_item(table_name: @table_name, key: name).item
  expect(@result).to be
  expect(@result['Value']).not_to eq @value
end

When(/^I retrieve a value from the keystore$/) do
  @dynamo = Aws::DynamoDB::Client.new region: @region
  @kms = Aws::KMS::Client.new region: @region
  keystore = Keystore.new dynamo: @dynamo, table_name: @table_name, kms: @kms, key_id: @key_id, key_alias: @key_alias
  keystore.store key: @key, value: @value
  @result = keystore.retrieve key: @key
  expect(@result).to be
end

Then(/^I should get that data back in plaintext$/) do
  keystore = Keystore.new dynamo: @dynamo, table_name: @table_name, kms: @kms
  @result = keystore.retrieve key: @key
  expect(@result).to eq @value
end

When(/^I retrieve a value using the command line interface$/) do
  # add the data to look up
  @dynamo = Aws::DynamoDB::Client.new region: @region
  @kms = Aws::KMS::Client.new region: @region
  keystore = Keystore.new dynamo: @dynamo, table_name: @table_name, kms: @kms, key_id: @key_id, key_alias: @key_alias
  keystore.store key: "#{@key}-cli", value: @value

  command = "bin/keystore.rb retrieve --table #{@table_name} --keyname #{@key}-cli"
  `#{command}`
end

Then(/^I should get that CLI entered data back in plaintext$/) do
  @dynamo = Aws::DynamoDB::Client.new region: @region
  @kms = Aws::KMS::Client.new region: @region
  keystore = Keystore.new dynamo: @dynamo, table_name: @table_name, kms: @kms
  @result = keystore.retrieve key: "#{@key}-cli"
  expect(@result).to eq @value
end

When(/^I store a value using the command line interface$/) do
  kmsoption = if @key_id
                "--kmsid #{@key_id}"
              else
                "--kmsalias #{@key_alias}"
              end
  command = "bin/keystore.rb store --table #{@table_name} --keyname #{@key}-cli --value #{@value}-cli #{kmsoption}"
  `#{command}`
end

Then(/^I should see that encrypted data from the CLI in the raw data store$/) do
  @dynamo = Aws::DynamoDB::Client.new region: @region
  @kms = Aws::KMS::Client.new region: @region
  name = { 'ParameterName' => "#{@key}-cli" }
  @result = @dynamo.get_item(table_name: @table_name, key: name).item
  expect(@result.nil?).to be false
  expect(@result['Value']).not_to eq @value
end

When(/^I store an empty value in the keystore$/) do
  @dynamo = Aws::DynamoDB::Client.new region: @region
  @kms = Aws::KMS::Client.new region: @region
  keystore = Keystore.new dynamo: @dynamo, table_name: @table_name, kms: @kms, key_id: @key_id, key_alias: @key_alias
  keystore.store key: @key, value: ''
end

When(/^I retrieve an empty value from the keystore$/) do
  @dynamo = Aws::DynamoDB::Client.new region: @region
  @kms = Aws::KMS::Client.new region: @region
  keystore = Keystore.new dynamo: @dynamo, table_name: @table_name, kms: @kms, key_id: @key_id, key_alias: @key_alias
  keystore.store key: @key, value: ''
  @result = keystore.retrieve key: @key
  expect(@result).to be
  expect(@result.empty?).to be true
end

Then(/^I should get an empty string back$/) do
  keystore = Keystore.new dynamo: @dynamo, table_name: @table_name, kms: @kms
  @result = keystore.retrieve key: @key
  expect(@result).to eq ''
end

When(/^I store a blank value using the command line interface$/) do
  kmsoption = if @key_id
                "--kmsid #{@key_id}"
              else
                "--kmsalias #{@key_alias}"
              end
  command = "bin/keystore.rb store --table #{@table_name} --keyname #{@key}-cli #{kmsoption} --value ''"
  `#{command}`
end

When(/^I retrieve a blank value using the command line interface$/) do
  # add the data to look up
  @dynamo = Aws::DynamoDB::Client.new region: @region
  @kms = Aws::KMS::Client.new region: @region
  keystore = Keystore.new dynamo: @dynamo, table_name: @table_name, kms: @kms, key_id: @key_id, key_alias: @key_alias
  keystore.store key: "#{@key}-cli", value: ''

  command = "bin/keystore.rb retrieve --table #{@table_name} --keyname #{@key}-cli"
  `#{command}`
end

Then(/^I should get an empty string back in plaintext$/) do
  @dynamo = Aws::DynamoDB::Client.new region: @region
  @kms = Aws::KMS::Client.new region: @region
  keystore = Keystore.new dynamo: @dynamo, table_name: @table_name, kms: @kms
  @result = keystore.retrieve key: "#{@key}-cli"
  expect(@result.empty?).to be true
end
