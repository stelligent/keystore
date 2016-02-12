Feature: Storing encrypted values with API
    In order for my pipeline to utilize secret values
    I want to be able to easily store and retrieve encrypted values using an API

    Background:
        Given a region to operate in
        And a DynamoDB table to use
        And a KMS key id or KMS key alias to use
        And test data to use

    Scenario: Store encrypted values
        When I store a value in the keystore
        Then I should see that encrypted data in the raw data store

    Scenario: Store empty values as encrypted values
        When I store an empty value in the keystore
        Then I should see that encrypted data in the raw data store

    Scenario: Retrieve encrypted values
        When I retrieve a value from the keystore
        Then I should get that data back in plaintext

    Scenario: Retrieve encrypted empty values
        When I retrieve an empty value from the keystore
        Then I should get an empty string back

