package cognito

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/pkg/errors"
)

// following
// https://aws.amazon.com/premiumsupport/knowledge-center/decode-verify-cognito-json-token/
type awsWellKnowKeys struct {
	Keys []*awsWellKnowKey `json:"keys"`
}

type awsWellKnowKey struct {
	Alg string `json:"alg"`
	E   string `json:"e"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	Use string `json:"use"`
}

// later we might abstract fetchKeys with a simple interface in order to test easily without
// fetch real aws key
func (aws *Auth) fetchKeys() ([]*awsWellKnowKey, error) {
	url := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", aws.region, aws.userPoolID)
	resp, err := http.Get(url)
	if err != nil {
		return nil, errors.Wrap(err, "fail to fetch aws jwks")
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "fail to read aws jwks body")
	}
	keys := &awsWellKnowKeys{}
	err = json.Unmarshal(body, keys)
	if err != nil {
		return nil, errors.Wrap(err, "fail to unmarshal aws jwks body")
	}
	return keys.Keys, nil
}

// IDTokenPayload ...
type IDTokenPayload struct {
	Sub           string
	Aud           string
	EventId       string
	TokenUse      string
	Iss           string
	EmailVerified bool
	Email         string
	Username      string
	PreferName    string
	AuthTime      time.Duration
	Exp           time.Duration
	Iat           time.Duration
}

// AccessTokenPayload ...
type AccessTokenPayload struct {
	Sub      string
	EventId  string
	Scope    string
	TokenUse string
	Username string
	Iss      string
	Jti      string
	ClientId string
	AuthTime time.Duration
	Exp      time.Duration
	Iat      time.Duration
}
