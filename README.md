## Golang Authentication Service

#### Introduction
This is a complete authentication solution that you can clone and use directly with your web services. It uses MongoDB as a database but the database package can easily be switched out without affecting the rest of the code to make use of any other database of your choice.

#### Running Locally
*Note:- Make sure GO111MODULE is enabled*
- Get all dependencies :- `go get ./...`
- Edit `.env` file to setup crucial env variables for the service to run. The required ones are
    ```MONGO_URI, DB_NAME, URL, Scheme, Hostname, ClientScheme, ClientHostname, ClientURL, STAGE```
- Create a new collection in mongodb database called keys. Add a document with a field called `key` with value being whatever you'd like to use as API key for the API.
- Create a new collection in mongodb database called Secrets. Add 2 documents here as follows:
```
    {
        "type": "JWTPublicKey",
        "value": "<RSA512-JWT-Public-Key>"
    }
```
```
    {
        "type": "JWTPrivateKey",
        "value": "<RSA512-JWT-Private-Key>"
    }
```
- Once that is done, simply run `go build` and then `./authentication`

#### Deploy Directly To Heroku
[![Deploy](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy)
