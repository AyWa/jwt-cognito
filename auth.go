package cognito

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/big"
	"sync"
	"time"

	"crypto/rsa"

	"github.com/dgrijalva/jwt-go"
	"github.com/mitchellh/mapstructure"
)

// Auth ...
type Auth struct {
	// The key will be the `kid`
	awsKeys     map[string]*awsWellKnowKey
	region      string
	userPoolID  string
	awsKeysLock sync.RWMutex
}

// New ...
func New(region, userPoolID string) *Auth {
	return &Auth{
		region:     region,
		userPoolID: userPoolID,
		awsKeys:    map[string]*awsWellKnowKey{},
	}
}

// ValidateToken ...
func (aws *Auth) ValidateToken(tokenString string) (map[string]interface{}, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("token invalid: no kid")
		}
		awsKey, err := aws.getAwsKey(kid)
		if err != nil {
			return nil, err
		}

		if token.Method.Alg() != awsKey.Alg {
			return nil, errors.New("token invalid: alg invalid")
		}

		return getPublicKey(awsKey.E, awsKey.N)
	})

	if err != nil {
		return nil, err
	}

	claim, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("token not valid")
	}

	return claim, nil
}

// ValidateAccessToken accessToken
func (aws *Auth) ValidateAccessToken(accessToken string) (*AccessTokenPayload, error) {
	rawValues, err := aws.ValidateToken(accessToken)
	if err != nil {
		return nil, err
	}
	convertTimeStamp(rawValues)
	values := &AccessTokenPayload{}
	if err := mapstructure.Decode(rawValues, values); err != nil {
		return nil, err
	}
	return values, nil
}

// ValidateIDToken can be call to validate a idToken.
func (aws *Auth) ValidateIDToken(IDToken string) (*IDTokenPayload, error) {
	rawValues, err := aws.ValidateToken(IDToken)
	if err != nil {
		return nil, err
	}
	convertTimeStamp(rawValues)
	values := &IDTokenPayload{}
	if err := mapstructure.Decode(rawValues, values); err != nil {
		return nil, err
	}
	return values, nil
}

func (aws *Auth) getAwsKey(k string) (*awsWellKnowKey, error) {
	aws.awsKeysLock.RLock()
	v, ok := aws.awsKeys[k]
	aws.awsKeysLock.RUnlock()
	// kind of lazy loading. If the key is not present we will refresh
	// we might need to add mutex to be safe later...
	if !ok {
		keys, err := aws.fetchKeys()
		if err != nil {
			return nil, err
		}
		aws.awsKeysLock.Lock()
		for _, key := range keys {
			aws.awsKeys[key.Kid] = key
		}
		aws.awsKeysLock.Unlock()
	}

	aws.awsKeysLock.RLock()
	v, ok = aws.awsKeys[k]
	aws.awsKeysLock.RUnlock()
	if !ok {
		return nil, errors.New("kid: " + k + " is not found")
	}
	return v, nil
}

// later need to move to mapstruct if possible
func convertTimeStamp(raw map[string]interface{}) {
	expTime := getTimeStamp(raw["exp"])
	if expTime != nil {
		raw["exp"] = expTime
	}
	iatTime := getTimeStamp(raw["iat"])
	if iatTime != nil {
		raw["iat"] = iatTime
	}
	authTime := getTimeStamp(raw["auth_time"])
	if authTime != nil {
		raw["auth_time"] = authTime
	}
}

func getTimeStamp(raw interface{}) *time.Time {
	i, ok := raw.(float64)
	if !ok {
		return nil
	}
	tm := time.Unix(int64(i), 0)
	tm = tm.UTC()
	return &tm
}

func getPublicKey(rawE, rawN string) (*rsa.PublicKey, error) {
	decodedE, err := base64.RawURLEncoding.DecodeString(rawE)
	if err != nil {
		return nil, errors.New("public key exponent is invalid")
	}

	// ensure we have a 32 bit number
	if len(decodedE) > 4 {
		return nil, errors.New("exponent should be a 32 bits number")
	}

	// ensure that we have a 32 bit number. For exanple if we got only 1 byte
	// we add the missing bytes
	e32 := make([]byte, 4)
	copy(e32[4-len(decodedE):], decodedE)
	e := int(binary.BigEndian.Uint32(e32))

	decodedN, err := base64.RawURLEncoding.DecodeString(rawN)
	if err != nil {
		return nil, errors.New("public key modulus is invalid")
	}

	n := new(big.Int)
	n.SetBytes(decodedN)

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}
