Feature: Storing encrypted values with CLI
    In order for my pipeline to utilize secret values
    I want to be able to easily store and retrieve encrypted values using a CLI tool

    Background:
        Given a region to operate in
        And a DynamoDB table to use
        And a KMS key id or KMS key alias to use
        And test data to use

    @flakey
    Scenario: Store using command line interface
        When I store a value using the command line interface
        Then I should see that encrypted data from the CLI in the raw data store

    Scenario: Retrieve encrypted values
        When I retrieve a value using the command line interface
        Then I should get that CLI entered data back in plaintext

    Scenario: Store a blank value using command line interface
        When I store a blank value using the command line interface
        Then I should see that encrypted data from the CLI in the raw data store

    Scenario: Retrieve a blank value using the command line inteface
        When I retrieve a blank value using the command line interface
        Then I should get an empty string back in plaintext

