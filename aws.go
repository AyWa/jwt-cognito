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
	Sub           string    `mapstructure:"sub"`
	Aud           string    `mapstructure:"aud"`
	EventID       string    `mapstructure:"event_id"`
	TokenUse      string    `mapstructure:"token_use"`
	Iss           string    `mapstructure:"iss"`
	EmailVerified bool      `mapstructure:"email_verified"`
	Email         string    `mapstructure:"email"`
	Username      string    `mapstructure:"cognito:username"`
	PreferName    string    `mapstructure:"preferred_username"`
	AuthTime      time.Time `mapstructure:"auth_time"`
	Exp           time.Time `mapstructure:"exp"`
	Iat           time.Time `mapstructure:"iat"`
}

// AccessTokenPayload ...
type AccessTokenPayload struct {
	Sub      string    `mapstructure:"sub"`
	EventID  string    `mapstructure:"event_id"`
	Scope    string    `mapstructure:"scope"`
	TokenUse string    `mapstructure:"token_use"`
	Username string    `mapstructure:"username"`
	Iss      string    `mapstructure:"iss"`
	Jti      string    `mapstructure:"jti"`
	ClientID string    `mapstructure:"client_id"`
	AuthTime time.Time `mapstructure:"auth_time"`
	Exp      time.Time `mapstructure:"exp"`
	Iat      time.Time `mapstructure:"iat"`
}
