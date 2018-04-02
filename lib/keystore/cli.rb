require 'aws-sdk-core'
begin
  require 'aws-sdk-dynamodb'
  require 'aws-sdk-kms'
rescue LoadError
  nil
end
require 'english'
require 'keystore'
require 'optparse'

# rubocop:disable ClassLength

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
      @keystore = Keystore.new dynamo: @dynamo, kms: @kms,
                               table_name: @opts[:table],
                               key_id: @opts[:kmsid],
                               key_alias: @opts[:kmsalias],
                               keystore_format: @opts[:keystore_format]
    end

    def run
      parse_arguments
      init_clients

      case @opts[:verb]
      when :store
        @keystore.store key: @opts[:keyname], value: @opts[:value]
      when :retrieve
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
        opts.separator usage.gsub(/^          /, '')
      end
    end
    # rubocop:enable Metrics/MethodLength

    # rubocop:disable Metrics/MethodLength

    def subcommands_args
      {
        store: {
          op: OptionParser.new do |opts|
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
            opts.on('-t', '--table=TABLE',
                    'DynamoDB table to retrieve/store from') do |t|
              @opts[:table] = t
            end
          end,
          mandatory: %i[value keyname table]
        },
        retrieve: {
          op: OptionParser.new do |opts|
            opts.banner = "Usage: #{$PROGRAM_NAME} retrieve [options]"
            opts.on('-k', '--keyname=KEY',
                    'keystore key to retrieve/store') do |k|
              @opts[:keyname] = k
            end
            opts.on('-t', '--table=TABLE',
                    'DynamoDB table to retrieve/store from') do |t|
              @opts[:table] = t
            end
          end,
          mandatory: %i[keyname table]
        }
      }
    end
    # rubocop:enable Metrics/MethodLength

    # rubocop:disable Metrics/MethodLength

    def parse_arguments
      argv_subcommand = (optparse = global_args).order(argv)
      command = @opts[:verb] = argv_subcommand.shift.to_sym
      subcommand = subcommands_args[command]
      raise OptionParser::MissingArgument unless subcommand
      optparse = subcommand[:op]
      optparse.order!(argv_subcommand)
      missing = subcommand[:mandatory].select { |param| @opts[param].nil? }
      unless missing.empty?
        raise OptionParser::MissingArgument, missing.join(', ')
      end
    rescue OptionParser::InvalidOption, OptionParser::MissingArgument
      puts $ERROR_INFO.to_s + "\n" + optparse
      exit
    end
    # rubocop:enable Metrics/MethodLength

    private

    def argv; ARGV; end # rubocop:disable SingleLineMethods
  end
end
