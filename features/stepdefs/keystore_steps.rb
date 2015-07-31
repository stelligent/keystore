require 'aws-sdk-core'
require 'keystore'

Given(/^test data to use$/) do
  @key = "testkey#{Time.now.strftime '%Y%m%d%H%M%S'}"
  @value = "testvalue#{Time.now.strftime '%Y%m%d%H%M%S'}"
end

Given(/^a region to operate in$/) do
  @region = ENV['region']
  fail if @region.nil?
end

Given(/^a KMS key id to use$/) do
  @key_id = ENV['key_id']
  fail if @key_id.nil?
end

Given(/^a DynamoDB table to use$/) do
  @table_name = ENV['table_name']
  fail if @table_name.nil?
end

When(/^I store a value in the keystore$/) do
  @dynamo = Aws::DynamoDB::Client.new region: @region
  @kms = Aws::KMS::Client.new region: @region
  keystore = Keystore.new dynamo: @dynamo, table_name: @table_name, kms: @kms, key_id: @key_id
  keystore.store key: @key, value: @value
end

Then(/^I should see that encrypted data in the raw data store$/) do
  name = { 'ParameterName' => @key }
  result = @dynamo.get_item(table_name: @table_name, key: name).item
  expect(result).to be
  expect(result['Value']).not_to eq @value
end

When(/^I retrieve a value from the keystore$/) do
  @dynamo = Aws::DynamoDB::Client.new region: @region
  @kms = Aws::KMS::Client.new region: @region
  keystore = Keystore.new dynamo: @dynamo, table_name: @table_name, kms: @kms, key_id: @key_id
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
  keystore = Keystore.new dynamo: @dynamo, table_name: @table_name, kms: @kms, key_id: @key_id
  keystore.store key: "#{@key}-cli", value: @value

  command = "ruby bin/keystore.rb retrieve --table #{@table_name} --keyname #{@key}-cli"
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
  command = "ruby bin/keystore.rb store --table #{@table_name} --keyname #{@key}-cli --kmsid #{@key_id} --value #{@value}-cli"
  `#{command}`
end

Then(/^I should see that encrypted data from the CLI in the raw data store$/) do
  @dynamo = Aws::DynamoDB::Client.new region: @region
  @kms = Aws::KMS::Client.new region: @region
  name = { 'ParameterName' => "#{@key}-cli" }
  result = @dynamo.get_item(table_name: @table_name, key: name).item
  expect(result).to be
  expect(result['Value']).not_to eq @value
end
