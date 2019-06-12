package cognito

import (
	"crypto/rsa"
	"math/big"
	"reflect"
	"testing"
	"time"
)

// later might be better to move that in testdata folder
const (
	validTestIDToken                = "eyJhbGciOiJSUzI1NiIsImtpZCI6IktJRHhhIn0.eyJzdWIiOiIzYTlmMmYzYS1lNjU5LTQxZGEtYjExNi0wOTAyZDFmN2Q0ZWEiLCJhdWQiOiIxNnA2bTgwM2hkbW12cXMwYmJ2aW5mYjlwdCIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJldmVudF9pZCI6IjUwM2I5Mjg1LTc1ZmMtNDI5Zi05NmZlLWJlN2QwODEyOWUzZSIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNTYwMzM5MzU5LCJpc3MiOiJodHRwczovL3R4dC5jb20iLCJjb2duaXRvOnVzZXJuYW1lIjoibWFyYy50dHRAZ21haWwuY29tIiwicHJlZmVycmVkX3VzZXJuYW1lIjoibWFyYyIsImV4cCI6OTU2MDM0Mjk2MCwiaWF0IjoxNTYwMzM5MzU5LCJlbWFpbCI6Im1hcmMudHR0QGdtYWlsLmNvbSJ9.i1g025WmvAVx6JZn9YtlsZJFTJaTDo1Eb93gtpg9FEtvGpn_kES4FO-wEzQR2F0dJF-f-qlGOoKzKbS385ky6nDV4hKAQjGAPeaG3CuT6fKnfKuidTeGFpH-SwYSycRi_hKPyy2R21k0grmIZCtR1jm0Bb4F42szTVduUX1bZYBFlb5Y_V0lckU5IpQVzimoeepYCsIMKRYUEChMLnEwVw10WcbyBGJqX4bICB4Zl-iDbAUV5_Z3U-RDeIcVvXgcEjjNthE4MuS4mGzfASMsBTDIGCNPpGmqnSRiJDBYAyK7i2ne87-EGgbBmh4QSqMVIvtyX7FCd_KQoyi2uFrrnw"
	expiredTestIDToken              = "eyJhbGciOiJSUzI1NiIsImtpZCI6IktJRHhhIn0.eyJzdWIiOiIzYTlmMmYzYS1lNjU5LTQxZGEtYjExNi0wOTAyZDFmN2Q0ZWEiLCJhdWQiOiIxNnA2bTgwM2hkbW12cXMwYmJ2aW5mYjlwdCIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJldmVudF9pZCI6IjUwM2I5Mjg1LTc1ZmMtNDI5Zi05NmZlLWJlN2QwODEyOWUzZSIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjo1NjAzMzkzNTksImlzcyI6Imh0dHBzOi8vdHR0LmNvbSIsImNvZ25pdG86dXNlcm5hbWUiOiJtYXJjLnR0dEBnbWFpbC5jb20iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJtYXJjIiwiZXhwIjo1NjAzNDI5NjAsImlhdCI6NTYwMzM5MzYwLCJlbWFpbCI6Im1hcmMudHR0QGdtYWlsLmNvbSJ9.OAXVnw-lTjyMWIApI0umVQ635tMHcBmaGKYDbluUe-Vagj9fNYpL0re_L-U-AJ0ZIQLlEgRzaoCxub8sqqB9mIleYHbcfwoEdgwYx96JcuLTh5Jt4KfwwLmVdBxwbI_w7xHnpR9hld9qEYexKhmJdRmrYP-uleOVoHW4kw4f53WBlk2xFMdnn-smwURDCuCYkCsEYUAz6C0MID_xqVsNFeGcea9Li6rC69bJK55jSVa1-pUvyRWD6XqzcPYN_SpMmRtV7lxBb9hQVvRnWwM00frM0HKPE90rW8wsC-ALF-UO6O_M3vfoKZA8mHjVJZRc8ImnJ5tU7hjcuS2Ne2cpHA"
	invalidSignatureTestIDToken     = "eyJhbGciOiJSUzI1NiIsImtpZCI6IktJRHhhIn0.eyJzdWIiOiIzYTlmMmYzYS1lNjU5LTQxZGEtYjExNi0wOTAyZDFmN2Q0ZWEiLCJhdWQiOiIxNnA2bTgwM2hkbW12cXMwYmJ2aW5mYjlwdCIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJldmVudF9pZCI6IjUwM2I5Mjg1LTc1ZmMtNDI5Zi05NmZlLWJlN2QwODEyOWUzZSIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNTYwMzM5MzU5LCJpc3MiOiJodHRwczovL3R4dC5jb20iLCJjb2duaXRvOnVzZXJuYW1lIjoibWFyYy50dHRAZ21haWwuY29tIiwicHJlZmVycmVkX3VzZXJuYW1lIjoibWFyYyIsImV4cCI6OTU2MDM0Mjk2MCwiaWF0IjoxNTYwMzM5MzU5LCJlbWFpbCI6Im1hcmMudHR0QGdtYWlsLmNvbSJ9.i1g025WmvAVx6JZn9YtlsZJFTJaTDo1Eb93gtpg9FEtvGpn_kES4FO-wEzQR2F0dJF-f-qlGOoKzKbS385ky6nDV4hKAQjGAPeaG3CuT6fKnfKuidTeGFpH-SwYSycRi_hKPyy2R21k0grmIZCtR1jm0Bb4F42szTVduUX1bZYBFlb5Y_V0lckU5IpQVzimoeepYCsIMKRYUEChMLnEwVw10WcbyBGJqX4bICB4Zl-iDbAUV5_Z3U-RDeIcVvXgcEjjNthE4MuS4mGzfASMsBTDIGCNPpGmqnSRiJDBYAyK7i2ne87-QGgbBmh4QSqMVIvtyX7FCd_KQoyi2uFrrnw"
	validTestAccessToken            = "eyJhbGciOiJSUzI1NiIsImtpZCI6IktJRHhhIn0.eyJzdWIiOiIzYTlmMmYzYS1lNjU5LTQxZGEtYjExNi0wOTAyZDFmN2Q0ZWEiLCJldmVudF9pZCI6IjUwM2I5Mjg1LTc1ZmMtNDI5Zi05NmZlLWJlN2QwODEyOWUzZSIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJhdXRoX3RpbWUiOjU2MDMzOTM1OSwiaXNzIjoiaHR0cHM6Ly90dHQuY29tIiwiZXhwIjo5NTYwMzQyOTYwLCJpYXQiOjU2MDMzOTM1OSwianRpIjoiODQ5ODUwZWEtYzlmYy00MTllLWIwZTUtN2ViNDZkOWQ2NWNjIiwiY2xpZW50X2lkIjoiMTZwNm04MDNoZG1tdnFzMGJidmluZmI5cHQiLCJ1c2VybmFtZSI6Im1hcmMudHR0QGdtYWlsLmNvbSJ9.ipZNEgm_DV0VA6_2h5ksin-bVQtuNyfBGGsbjPokZ87fPoO2onVD3--DimJL86ggDONxAzlojXkVAfJeyITfuz33tzLX__YObTIE1tLy3854X4HwDsua-I2CjP5gjjIEBKVRc2uMs8fe2Jk7G9aZ85zM2oyoB7s8QMNwe49CakRawLbKcrarWrRwRLdN0f2G44ZyKrGRWP0Q2PMcy_iViAs54ijxPf01ZExRf-x99bsQfCfPnkCp0DVEh-WGBVlotndTaOckUdvg_rJr_qTS95VBsRsb2S3K5xarMOq9nCkdtaaNuN5MVt5v-ThdFSNQ5aB747Y3Y8HuTNsuhwdqpw"
	expiredTestAccessToken          = "eyJhbGciOiJSUzI1NiIsImtpZCI6IktJRHhhIn0.eyJzdWIiOiIzYTlmMmYzYS1lNjU5LTQxZGEtYjExNi0wOTAyZDFmN2Q0ZWEiLCJldmVudF9pZCI6IjUwM2I5Mjg1LTc1ZmMtNDI5Zi05NmZlLWJlN2QwODEyOWUzZSIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJhdXRoX3RpbWUiOjU2MDMzOTM1OSwiaXNzIjoiaHR0cHM6Ly90dHQuY29tIiwiZXhwIjo1NjAzNDI5NjAsImlhdCI6NTYwMzM5MzYwLCJqdGkiOiI4NDk4NTBlYS1jOWZjLTQxOWUtYjBlNS03ZWI0NmQ5ZDY1Y2MiLCJjbGllbnRfaWQiOiIxNnA2bTgwM2hkbW12cXMwYmJ2aW5mYjlwdCIsInVzZXJuYW1lIjoibWFyYy50dHRAZ21haWwuY29tIn0.kIP_A_WScbyXfizL-jZSGT5Ywd_tpnAozBsGpGl0S7ny4x23vG_amCe2x4PvOZr08xFPe_7IeaYvvczHJggdcS_myiDlpQ0LVulhc4kyhflHruV3TjjqtObAe4kBwlrrjiG-YrxjUfvOPUqTx0MlXjRxX0Rji_Va0gmJX2nDunSaU2KVNQKs5cLPwzQ-KryLZqw8Lr_dikJXRxJwBQk-EvtL79HsDRmp8qjSh_cDf0HiyWeutwxW87KSRgAyYftoI91hrzmA7FcZVua8OynyLyf5HnwIkRFKUp8I6xjv1KOc37sCGymegQerNeSyduhX3f_CpdCQ1-RlAhtLHmhuQg"
	invalidSignatureTestAccessToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IktJRHhhIn0.eyJzdWIiOiIzYTlmMmYzYS1lNjU5LTQxZGEtYjExNi0wOTAyZDFmN2Q0ZWEiLCJldmVudF9pZCI6IjUwM2I5Mjg1LTc1ZmMtNDI5Zi05NmZlLWJlN2QwODEyOWUzZSIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJhdXRoX3RpbWUiOjU2MDMzOTM1OSwiaXNzIjoiaHR0cHM6Ly90dHQuY29tIiwiZXhwIjo5NTYwMzQyOTYwLCJpYXQiOjU2MDMzOTM1OSwianRpIjoiODQ5ODUwZWEtYzlmYy00MTllLWIwZTUtN2ViNDZkOWQ2NWNjIiwiY2xpZW50X2lkIjoiMTZwNm04MDNoZG1tdnFzMGJidmluZmI5cHQiLCJ1c2VybmFtZSI6Im1hcmMudHR0QGdtYWlsLmNvbSJ9.ipZNEgm_DV0VA6_2h5ksin-bVQtuNyfBGGsbjPokZ87fPoO2onVD3--DimJL86ggDONxAzlojXkVAfJeyITfuz33tzLX__YObTIE1tLy3854X4HwDsua-I2CjP5gjjIEBKVRc2uMs8fe2Jk7G9aZ85zM2oyoB7s8QMNwe49CakRawLbKcrarWrRwRLdN0f2G44ZyKrGRWP0Q2PMcy_iViAs54ijxPf01ZExRf-x99bsQfCfPnkCp0DVEh-WGBVlotndTaOckUdvg_rJr_qTS95VBsRsb2S3K5xarMOq9nCkdtaaNuN5MVt5v-QhdFSNQ5aB747Y3Y8HuTNsuhwdqpw"
)

// not a real aws key, but just the public used for the test token
var testValidawsKeys = map[string]*awsWellKnowKey{
	"KIDxa": &awsWellKnowKey{
		Alg: "RS256",
		E:   "AQAB",
		Kid: "KIDxa",
		Kty: "RSA",
		N:   "AJ88orNWY3zQdGwYChTEr75E7cJbwbGiau0ucAPpM3lTlaVVsJFnVYWuLN_FzP6Wv8q-O2r-_s91U5rw0cgB3Gk_dsIURBaS7_XI-ZU3iUom8q_zK5v2LYwmVVoGjmCIcK18Ci6j6_9dYp1rAJHyMrbx1k8WWBHFy4AFxblLmkt7hfYBIjUMMxk1Nb9BapKkwa-AfJ1txwjeO11LtLfGNHvpX-LODsUGsFg-_Sff-Xd0ctL21dwJtRbRiYibzsEbCH1QoQ6WErU3B0wjKrb1m1ei9dQVpKcxl0luB7-N6mvhkmDg9kFOvDG-faEpNjgfgbTi6SaH5mxhBoL5sMgiPTM",
		Use: "sig",
	},
}

func TestAuth_getAwsKey(t *testing.T) {
	type fields struct {
		awsKeys    map[string]*awsWellKnowKey
		region     string
		userPoolID string
	}
	type args struct {
		k string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *awsWellKnowKey
		wantErr bool
	}{
		{
			"should successfully get from cache",
			fields{
				awsKeys: map[string]*awsWellKnowKey{
					// given a key in cache
					"kxxxxxID": &awsWellKnowKey{
						Alg: "RS256",
						E:   "AQAB",
						Kid: "kxxxxxID",
						Kty: "RSA",
						N:   "xxxx",
						Use: "sig",
					},
				},
				region:     "",
				userPoolID: "",
			},
			args{k: "kxxxxxID"},
			&awsWellKnowKey{
				Alg: "RS256",
				E:   "AQAB",
				Kid: "kxxxxxID",
				Kty: "RSA",
				N:   "xxxx",
				Use: "sig",
			},
			false,
		},
		{
			"should successfully get from remote (test1)",
			fields{
				awsKeys:    map[string]*awsWellKnowKey{},
				region:     "us-east-1",
				userPoolID: "us-east-1_MQnn7mzKZ",
			},
			args{k: "03oly5+cLzmYbfTUlI1Zebd5/rMaQNND5kgFXhP8s/0="},
			&awsWellKnowKey{
				Alg: "RS256",
				E:   "AQAB",
				Kid: "03oly5+cLzmYbfTUlI1Zebd5/rMaQNND5kgFXhP8s/0=",
				Kty: "RSA",
				N:   "slmdpk2Y6267KcI49coGvIPU3DKwOhUtKMIAfOgm8J5_Z56Sk85pmeGhqEtFNMbmuP89W-Ea80VAgBKNtzMWYV-YJOR94wpMH37NvrgedLa_zdjg2oGfAuJjSZChrjbvHcU8STm0SxzrdvlX55al9FCzUSa6jq30tUbKeCJGludsjJImLUOv4qwYaYdWbmYUQjWrkisxg15ADpJglsRdMF4mB48OlsI44zP7gRIVrjZwSWvQ11zby1bRid3POqPxejkYz1Nd98eEumDdYUrxRXuKaNzyJ42roQMjfpbY46n-XDdmM53nxJNFwcRKbsLMSmvPFkezxXNw201RB1CKzQ",
				Use: "sig",
			},
			false,
		},
		{
			"should successfully get from remote (test2)",
			fields{
				awsKeys:    map[string]*awsWellKnowKey{},
				region:     "us-east-1",
				userPoolID: "us-east-1_MQnn7mzKZ",
			},
			args{k: "XN9pj9+EdO59lukoJBhxDbWkFS6x3xaM2OG21lbt2bQ="},
			&awsWellKnowKey{
				Alg: "RS256",
				E:   "AQAB",
				Kid: "XN9pj9+EdO59lukoJBhxDbWkFS6x3xaM2OG21lbt2bQ=",
				Kty: "RSA",
				N:   "pAb8ODqcckFiC5gWOEFKAtv7qGl4tpbutUTRBIsVLfcO--Mu3V7qS3K9QFDM6P-6DmqavL9-q1uavcxiwANXkCUkA_9tREFYmUNGBYd3aAxjHtOWpE82agA10BpO-bL02ES2G66LBlYBsOyv6PpZTW7Dqd17pkn42le7_IOFneaoXhKsm-XkwNfk9PLgG814k5FjrrYVw1_fiPCiag4blQHSGHaDggH9NGRzobS7MZMYQ05QU6gsIDCPcYm0u-hOm8gKshsWqWcTELHfd8_MA5M6hPYhqa-HxAvDV-BCCoRCvatLWhsTEUjI_-2I9zgg9x9uAN1A6r8E1wviVIyDHQ",
				Use: "sig",
			},
			false,
		},
		{
			"should return error if key does not exist",
			fields{
				awsKeys:    map[string]*awsWellKnowKey{},
				region:     "us-east-1",
				userPoolID: "us-east-1_MQnn7mzKZ",
			},
			args{k: "kxxxxxID"},
			nil,
			true,
		},
		{
			"should return error if aws settings are invalid",
			fields{
				awsKeys:    map[string]*awsWellKnowKey{},
				region:     "",
				userPoolID: "",
			},
			args{k: "kxxxxxID"},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aws := &Auth{
				awsKeys:    tt.fields.awsKeys,
				region:     tt.fields.region,
				userPoolID: tt.fields.userPoolID,
			}
			got, err := aws.getAwsKey(tt.args.k)
			if (err != nil) != tt.wantErr {
				t.Errorf("Auth.getAwsKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Auth.getAwsKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getPublicKey(t *testing.T) {
	n1, n2 := new(big.Int), new(big.Int)
	n1, _ = n1.SetString("22514609491254403646416663439804096716857417948176452860855484730621642754774701635367121190160893384310911581694152651392213373857555832529418382671012421055100224200429653581495759074865033759236175375043343524724423875735054925403537489760321791525168713681208511033844509995630859637614999500579458837232162985290502847982138761209111263549695056726161199419727777686852941936768385592302794205035164995521504547932003985847396134071473434911245764305379951715697466834773896908729809739492089594933623556361254659179927690681540529726277721710390221041568363895082358641384675173557038659887026850931962482297549", 10)
	n2, _ = n2.SetString("20706526561198870091127536718382695061145408127349293203310057584732556609428859112045634114845982411350514905127003843845846152147209218958716318547778144089215117821295287792365078984855332563080129735583539553142038811974426628679398994057923746620763170942769275849136015376470557587946622109813412348382257203335660645702991893507791746999400159150496033968975717946181341873475485526057398118026396370502008448760310209734712520708286161070772571818744277436414606472891456409282814071191701147460810766221769767851891243946870624298090047645317674862757790918805351609802007837131051760614432882007933948035869", 10)
	type args struct {
		rawE string
		rawN string
	}
	tests := []struct {
		name    string
		args    args
		want    *rsa.PublicKey
		wantErr bool
	}{
		{
			"should convert correctly raw base 64 (test1)",
			args{rawE: "AQAB", rawN: "slmdpk2Y6267KcI49coGvIPU3DKwOhUtKMIAfOgm8J5_Z56Sk85pmeGhqEtFNMbmuP89W-Ea80VAgBKNtzMWYV-YJOR94wpMH37NvrgedLa_zdjg2oGfAuJjSZChrjbvHcU8STm0SxzrdvlX55al9FCzUSa6jq30tUbKeCJGludsjJImLUOv4qwYaYdWbmYUQjWrkisxg15ADpJglsRdMF4mB48OlsI44zP7gRIVrjZwSWvQ11zby1bRid3POqPxejkYz1Nd98eEumDdYUrxRXuKaNzyJ42roQMjfpbY46n-XDdmM53nxJNFwcRKbsLMSmvPFkezxXNw201RB1CKzQ"},
			&rsa.PublicKey{
				N: n1,
				E: 65537,
			},
			false,
		},
		{
			"should convert correctly raw base 64 (test2)",
			args{rawE: "AQAB", rawN: "pAb8ODqcckFiC5gWOEFKAtv7qGl4tpbutUTRBIsVLfcO--Mu3V7qS3K9QFDM6P-6DmqavL9-q1uavcxiwANXkCUkA_9tREFYmUNGBYd3aAxjHtOWpE82agA10BpO-bL02ES2G66LBlYBsOyv6PpZTW7Dqd17pkn42le7_IOFneaoXhKsm-XkwNfk9PLgG814k5FjrrYVw1_fiPCiag4blQHSGHaDggH9NGRzobS7MZMYQ05QU6gsIDCPcYm0u-hOm8gKshsWqWcTELHfd8_MA5M6hPYhqa-HxAvDV-BCCoRCvatLWhsTEUjI_-2I9zgg9x9uAN1A6r8E1wviVIyDHQ"},
			&rsa.PublicKey{
				N: n2,
				E: 65537,
			},
			false,
		},
		{
			"should fail to convert invalid N",
			args{rawE: "AQAB", rawN: "!@#!@#!$!@"},
			nil,
			true,
		},
		{
			"should fail to convert invalid E",
			args{rawE: "!@*#", rawN: "pAb8ODqcckFiC5gWOEFKAtv7qGl4tpbutUTRBIsVLfcO--Mu3V7qS3K9QFDM6P-6DmqavL9-q1uavcxiwANXkCUkA_9tREFYmUNGBYd3aAxjHtOWpE82agA10BpO-bL02ES2G66LBlYBsOyv6PpZTW7Dqd17pkn42le7_IOFneaoXhKsm-XkwNfk9PLgG814k5FjrrYVw1_fiPCiag4blQHSGHaDggH9NGRzobS7MZMYQ05QU6gsIDCPcYm0u-hOm8gKshsWqWcTELHfd8_MA5M6hPYhqa-HxAvDV-BCCoRCvatLWhsTEUjI_-2I9zgg9x9uAN1A6r8E1wviVIyDHQ"},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getPublicKey(tt.args.rawE, tt.args.rawN)
			if (err != nil) != tt.wantErr {
				t.Errorf("getPublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getPublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuth_ValidateToken(t *testing.T) {
	type fields struct {
		awsKeys    map[string]*awsWellKnowKey
		region     string
		userPoolID string
	}
	type args struct {
		tokenString string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    map[string]interface{}
		wantErr bool
	}{
		{
			"should succeed: valid test key",
			fields{awsKeys: testValidawsKeys},
			args{validTestIDToken},
			map[string]interface{}{
				"sub":                "3a9f2f3a-e659-41da-b116-0902d1f7d4ea",
				"aud":                "16p6m803hdmmvqs0bbvinfb9pt",
				"email_verified":     true,
				"event_id":           "503b9285-75fc-429f-96fe-be7d08129e3e",
				"token_use":          "id",
				"auth_time":          1.560339359e+09,
				"iss":                "https://txt.com",
				"cognito:username":   "marc.ttt@gmail.com",
				"preferred_username": "marc",
				"exp":                9.56034296e+09,
				"iat":                1.560339359e+09,
				"email":              "marc.ttt@gmail.com",
			},
			false,
		},
		{
			"should return error: expired key",
			fields{awsKeys: testValidawsKeys},
			args{expiredTestIDToken},
			nil,
			true,
		},
		{
			"should return error: invalid signature",
			fields{awsKeys: testValidawsKeys},
			args{invalidSignatureTestIDToken},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aws := &Auth{
				awsKeys:    tt.fields.awsKeys,
				region:     tt.fields.region,
				userPoolID: tt.fields.userPoolID,
			}
			got, err := aws.ValidateToken(tt.args.tokenString)
			if (err != nil) != tt.wantErr {
				t.Errorf("Auth.ValidateToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Auth.ValidateToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuth_ValidateAccessToken(t *testing.T) {
	iat, _ := time.Parse(time.RFC3339, "1987-10-04T09:49:19.000Z")
	exp, _ := time.Parse(time.RFC3339, "2272-12-15T02:49:20.000Z")
	type fields struct {
		awsKeys    map[string]*awsWellKnowKey
		region     string
		userPoolID string
	}
	type args struct {
		accessToken string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *AccessTokenPayload
		wantErr bool
	}{
		{
			"should succeed: valid access token",
			fields{awsKeys: testValidawsKeys},
			args{validTestAccessToken},
			&AccessTokenPayload{
				Sub:      "3a9f2f3a-e659-41da-b116-0902d1f7d4ea",
				EventID:  "503b9285-75fc-429f-96fe-be7d08129e3e",
				TokenUse: "access",
				Scope:    "aws.cognito.signin.user.admin",
				Iss:      "https://ttt.com",
				Jti:      "849850ea-c9fc-419e-b0e5-7eb46d9d65cc",
				ClientID: "16p6m803hdmmvqs0bbvinfb9pt",
				Username: "marc.ttt@gmail.com",
				Exp:      exp,
				Iat:      iat,
				AuthTime: iat,
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aws := &Auth{
				awsKeys:    tt.fields.awsKeys,
				region:     tt.fields.region,
				userPoolID: tt.fields.userPoolID,
			}
			got, err := aws.ValidateAccessToken(tt.args.accessToken)
			if (err != nil) != tt.wantErr {
				t.Errorf("Auth.ValidateAccessToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Auth.ValidateAccessToken() = \n%v, \nwant \n%v", got, tt.want)
			}
		})
	}
}

func TestAuth_ValidateIDToken(t *testing.T) {
	iat, _ := time.Parse(time.RFC3339, "2019-06-12T11:35:59.000Z")
	exp, _ := time.Parse(time.RFC3339, "2272-12-15T02:49:20.000Z")
	type fields struct {
		awsKeys    map[string]*awsWellKnowKey
		region     string
		userPoolID string
	}
	type args struct {
		IDToken string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *IDTokenPayload
		wantErr bool
	}{
		{
			"should succeed: valid id token",
			fields{awsKeys: testValidawsKeys},
			args{validTestIDToken},
			&IDTokenPayload{
				Sub:           "3a9f2f3a-e659-41da-b116-0902d1f7d4ea",
				Aud:           "16p6m803hdmmvqs0bbvinfb9pt",
				EventID:       "503b9285-75fc-429f-96fe-be7d08129e3e",
				TokenUse:      "id",
				Iss:           "https://txt.com",
				EmailVerified: true,
				Email:         "marc.ttt@gmail.com",
				Username:      "marc.ttt@gmail.com",
				PreferName:    "marc",
				Exp:           exp,
				Iat:           iat,
				AuthTime:      iat,
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aws := &Auth{
				awsKeys:    tt.fields.awsKeys,
				region:     tt.fields.region,
				userPoolID: tt.fields.userPoolID,
			}
			got, err := aws.ValidateIDToken(tt.args.IDToken)
			if (err != nil) != tt.wantErr {
				t.Errorf("Auth.ValidateIDToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Auth.ValidateIDToken() = \n%v, \nwant \n%v", got, tt.want)
			}
		})
	}
}
