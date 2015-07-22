Feature: Storing encrypted values
    In order for my pipeline to utilize secret values
    I want to be able to easily store and retrieve encrypted values

    Background:
        Given a region to operate in
        And a DynamoDB table to use
        And a KMS key id to use
        And test data to use

    Scenario: Store encrypted values
        When I store a value in the keystore
        Then I should see that encrypted data in the raw data store

    Scenario: Retreieve encrypted values
        When I retrieve a value from the keystore
        Then I should get that data back in plaintext

    Scenario: Store using command line interface
        When I store a value using the command line interface
        Then I should see that encrypted data in the raw data store

    Scenario: Retreieve encrypted values
        When I retrieve a value using the command line interface
        Then I should get that data back in plaintext
