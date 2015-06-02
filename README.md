# keystore :key:

While building applications and continuous delivery pipelines, secret management is usually one of the first non-trivial problems you run across. The Keystore utility pairs to AWS services to handle encryption and storage of secret data.

The Keystore stores all data in a DynamoDB table, indexed on the key's name. All data is encrypted using the Key Management Service. Both this services have costs associated with them, but even at moderate use will still be cheaper than running an EC2 instance with key management software on it.

# usage :key:

## tests

You have rspec, cucumber, and rubocop installed right? (Also the nyan-cat rspec formatter because we are all very serious no-nonsense programmer types here.)

    gem install rspec cucumber rubocop nyan-cat-formatter
  
Okay, now from the the root of the repo you can do these things.

* To run the unit tests:

        rspec 

* To run static analysis:

        rubocop

* To run the integration tests, you'll need to set up a KMS Key manually and write down the key_id. Then, you'll need to set up a DynamoDB, but you can use the included cfn template for that.

        export AWS_ACCESS_KEY_ID=YOURACCESSKEY
        export AWS_SECRET_ACCESS_KEY=YOURSECRETKEY
        aws cloudformation create-stack --stack-name keystore-test-db --template-body file://config/dynamo.json
        echo "This takes a minute, so go get yourself a coffee." && sleep 60
        export table_name=`aws cloudformation describe-stacks --stack-name jonny-test-ddb --query Stacks[*].Outputs[*].OutputValue --output text`
        
* Then to run the integration tests

        cucumber region="us-east-1" table_name="$table_name" key_id="your-iam-kms-key-id" 

## api

    keystore = Keystore.new dynamo: Aws::DyanmoDB::Client.new, table_name: dynamo_db_table_name, kms: Aws::KMS::Client.new, key_id: your_kms_key_id
    
    keystore.store key: "key", value: "value"
    
    result = keystore.retrieve key: "key"

## cli 

tbd.  probably something like `keystore store --table table_name --key key_name --value value` and `keystore retrieve --table table_name --key key_name`

# license :key:

Copyright (c) 2014 Stelligent Systems LLC

MIT LICENSE

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
