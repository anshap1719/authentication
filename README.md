## Golang Authentication Service

#### Introduction
This is a complete authentication solution that you can clone and use directly with your web services. It uses MongoDB as a database but the database package can easily be switched out without affecting the rest of the code to make use of any other database of your choice.

#### Running Locally
*Note:- Make sure GO111MODULE is enabled*
- Get all dependencies :- `go get ./...`
- Edit `.env` file to setup crucial env variables for the service to run. The required ones are
    ```MONGO_URI, DB_NAME, URL, Scheme, Hostname, ClientScheme, ClientHostname, ClientURL, STAGE```
- Once that is done, simply run `go build` and then `./authentication`

#### Deploy Directly To Heroku
<div style="text-align: center">[![Deploy](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy)</div>