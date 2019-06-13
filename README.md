# jwt-cognito [![codecov](https://codecov.io/gh/AyWa/jwt-cognito/branch/master/graph/badge.svg)](https://codecov.io/gh/AyWa/jwt-cognito)
`jwt-cognito` is a helper package that will allow you to **validate** quickly and seamlessly jwt token created by [AWS cognito](https://aws.amazon.com/cognito/)
## Installation
`go get github.com/AyWa/jwt-cognito/cognito`
## Usage and examples
For more usage see the godoc ~
### Simple init and token check
```
import (
  "fmt"

  cognito "github.com/AyWa/jwt-cognito"
)

// Initialize the cognito helper: aws cognito region, aws cognito userPool id
auth := cognito.New("us-east-1", "us-east-1_XXXXXXX")

// validate a token
// It will return error if the token is not valid
payload, err := auth.ValidateToken("xx.yy.zz")
if err != nil {
  panic(err)
}

// you can use the payload to get the user info etc
fmt.Println(payload[email])
```