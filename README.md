# Prometheus

Java app for simulating malicious ssh traffic via AWS

## Requirements

AWS account with proper credentials

Permission to start instances

## Usage

You need to set up your AWS security credentials. You can do this by creating a file named "credentials" at ~/.aws/
(C:\Users\USER_NAME\.aws\ for Windows users) and saving the following lines in the file:

    [default]
    aws_access_key_id = <your access key id>
    aws_secret_access_key = <your secret key>

See the [Security Credentials](http://aws.amazon.com/security-credentials) page
for more information on getting your keys.

    gradlew build
    gradlew run

## TODO

- username is hardcoded to 'ubuntu'
- allow for command line configuration
- config file read/write via JSON

