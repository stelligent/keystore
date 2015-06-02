# keystore

While building applications and continuous delivery pipelines, secret management is usually one of the first non-trivial problems you run across. The Keystore utility pairs to AWS services to handle encryption and storage of secret data.

The Keystore stores all data in a DynamoDB table, indexed on the key's name. All data is (going to be...) encrypted using the Key Management Service. Both this services have costs associated with them, but even at moderate use will still be cheaper than running an EC2 instance with key management software on it.

# usage

## api

  ```keystore = Keystore.new dynamo: dynamodb_client, table_name: table_name
  keystore.store key: key, value: value```

  ```keystore = Keystore.new dynamo: dynamodb_client, table_name: table_name
  keystore.store key: key, value: value```

## cli 

tbd.  probably something like `keystore store --table table_name --key key_name --value value` and `keystore retrieve --table table_name --key key_name`

