Local AWS Cognito Server
========================

This is a barebones mock image for testing AWS Cognito & Pinpoint. It is ideal for Amplify JS or any other implementation of client side Pinpoint anayltics.

## API

The following AWS SDK API commands are supported:
 
- `GetId`: Returns a unique identity ID for a given Cognito Identity Pool ID.
- `GetCredentialsForIdentity`: Returns an object containing credentials you can use to create the Pinpoint Client.

## Docker compose usage

```
services:
  cognito:
    image: humanmade/local-cognito
    ports:
      - 3000
```

## Local Pinpoint

This image is a counterpart to [local-pinpoint](https://github.com/humanmade/local-pinpoint), they should be used together.
