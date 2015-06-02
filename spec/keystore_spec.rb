require_relative '../lib/keystore.rb'

# mock dynamo return value
class Result
  attr_accessor :item
  def initialize value
    @item = {"Value" => value}
  end
end


RSpec.describe "Keystore" do
  context "it can store encrypted values" do
    it "will call DynamoDB to store the value" do
      mock_ddb = double("AWS::DynamoDB::Client")
      expect(mock_ddb).to receive(:put_item)

      keystore = Keystore.new dynamo: mock_ddb, table_name: "dontcare"
      
      begin
        keystore.store key: "testkey", value: "testvalue"
      rescue Exception => e
        fail e
      end
    end
  end

  context "it can retrieve stored values" do
    it "will return data for a given key" do
      mock_ddb = double("AWS::DynamoDB::Client")
      expect(mock_ddb).to receive(:get_item).and_return(Result.new("testvalue"))

      keystore = Keystore.new dynamo: mock_ddb, table_name: "dontcare"

      begin
        keystore.retrieve key: "testkey"
      rescue Exception => e
        fail e
      end
    end
  end
end