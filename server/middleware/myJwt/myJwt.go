package myjwt

import (
	"io/ioutil"
	"time"

	"github.com/dgrijalva/jwt-go"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/simar/golang-csrf-project/db"
	"github.com/simar/golang-csrf-project/db/models"
)

const (
	privkeyPath = "keys/app.rsa"
	pubkeyPath  = "keys/app.rsa.pub"
)

func InitJWT() error {
	signBytes,err := ioutil.ReadFile(privkeyPath)
	if err!=nil{
		return err
	}
	signKey,err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err!=nil{
		return err
	}
	verifyBytes,err := ioutil.ReadFile(pubkeyPath)
	if err!=nil{
		return err
	}
	verifyKey,err = jwt.ParseRSAPrivateKeyFromPEM(verifyBytes)
	if err!=nil{
		return err
	}
	return nil
}

func CreateNewTokens(uuid string,role string)(authTokenString, refreshTokenString, csrfSecret string,err error) {

	//generate the CSRF secret
	csrfSecret,err = models.GenerateCSRFSecret()
	if err!=nil{
		return
	}

	//generating the refresh token
	refreshTokenString,err = CreateRefreshTokenString(uuid,role, csrfSecret)

	//generating the auth token
	authTokenString,err = createAuthTokenString(uuid, role, csrfSecret)
	if err!=nil{
		return
	}
	return
}

func createAuthTokenString(uuid string,role string,csrfSecret string)(authTokenString, err error) {
	authTokenExp := time.Now().Add(models.AuthTokenValidTime).Unix()
	authClaims := models.TokenClaims{
		jwt.StandardClaims{
			Subject:uuid,
			ExpiresAt:authTokenExp,
		},
		role,
		csrfSecret,
	}
	authJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"),authClaims)
	authTokenString,err = authJwt.SignedString(signKey)
	return
}

func CheckAndRefreshTokens(uuid string,role string,csrfString string)(refreshTokenString string, err string) {

	refreshTokenExp := time.Now().Add(models.RefreshTokenValidTime).Unix()
	refreshJti, err := db.StoreRefreshToken()
	if err!=nil{
		return
	}
	refreshClaims := models.TokenClaims{
		jwt.StandardClaims{
			Id:refreshJti,
			Subject: uuid,
			ExpiresAt:refreshTokenExp
		},
		role,
		csrfString,
	}
	refreshJWT := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"),refreshClaims)
	refreshTokenString,err = refreshJWT.SignedString(signKey)
	

}

func updateRefreshToken() {

}

func updateAuthTokenString() {

}

func RevokeRefreshToken() error {

}

func GrabUUID() {

}