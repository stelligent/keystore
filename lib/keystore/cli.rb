require 'aws-sdk-core'
begin
  require 'aws-sdk-dynamodb'
  require 'aws-sdk-kms'
rescue LoadError
  nil
end
require 'keystore'
require 'optparse'

class Keystore
  # keystore CLI handler
  class Cli
    def initialize
      # Defaults for options
      @opts = { region: 'us-east-1' }
    end

    def init_clients
      @dynamo = Aws::DynamoDB::Client.new region: @opts[:region]
      @kms = Aws::KMS::Client.new region: @opts[:region]
      @keystore = Keystore.new dynamo: dynamo,
                               table_name: @opts[:table],
                               kms: kms,
                               key_id: @opts[:kmsid],
                               key_alias: @opts[:kmsalias]
    end

    def run
      parse_arguments
      init_clients

      case @opts[:verb]
      when 'store'
        @keystore.store key: @opts[:keyname], value: @opts[:value]
      when 'retrieve'
        puts @keystore.retrieve(key: @opts[:keyname])
      else
        raise "unknown subcommand #{@opts[:verb]}"
      end
    end

    # rubocop:disable Metrics/MethodLength

    def global_args
      OptionParser.new do |opts|
        opts.banner = "Usage: #{$PROGRAM_NAME} [options] subcommand [options]"

        opts.on('--region=REGION',
                'AWS region to use (default us-east-1)') do |region|
          @opts[:region] = region
        end

        opts.on('-t', '--table=TABLE',
                'DynamoDB table to retrieve/store from') do |t|
          @opts[:table] = t
        end

        opts.separator ''
        usage = <<-USAGE
          available commands:

            store -- store a value in keystore
            retrieve -- retrieve a value from keystore

          use --help with either command for more information.
        USAGE
        opts.separator usage.gub(/^          /, '')
      end
    end
    # rubocop:enable Metrics/MethodLength

    # rubocop:disable Metrics/MethodLength

    def parse_arguments
      subcommands = {
        'store' => OptionParser.new do |opts|
          opts.banner = "Usage: #{$PROGRAM_NAME} store [options]"
          opts.on('-v', '--value=VALUE',
                  'Value to store in keystore') do |v|
            @opts[:value] = v
          end
          opts.on('-k', '--kmsid=KMSID',
                  'ID of KMS CMK to use') do |k|
            @opts[:kmsid] = k
          end
          opts.on('--kmsalias=KMSALIAS',
                  'Alias of KMS CMK to use') do |k|
            @opts[:kmsalias] = k
          end
          opts.on('-e', '--keyname=KEY',
                  'keystore key to retrieve/store') do |e|
            @opts[:keyname] = e
          end
        end,
        'retrieve' => OptionParser.new do |opts|
          opts.banner = "Usage: #{$PROGRAM_NAME} retrieve [options]"
          opts.on('-k', '--keyname=KEY',
                  'keystore key to retrieve/store') do |k|
            @opts[:keyname] = k
          end
        end
      }

      global_args.order! do |command|
        @opts[:verb] = command
        subcommands[command].order!
      end
    end
    # rubocop:enable Metrics/MethodLength
  end
end
