require 'aws-sdk-core'

class Keystore

  def initialize params = {} 
    @options = params
    raise "need to specify dynamo parameter" if @options[:dynamo].nil?
    raise "need to specify table_name parameter" if @options[:table_name].nil? 
    #@kms = params[:kms]
  end

  def store params 
    @options[:dynamo].put_item(:table_name => @options[:table_name], item: { "ParameterName" => params[:key], "Value" => params[:value] })
  end

  def retrieve params
    item = @options[:dynamo].get_item(table_name: @options[:table_name], key: { 'ParameterName' => params[:key] } ).item
    result = item["Value"]
    result
  end
end