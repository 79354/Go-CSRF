package myJwt

import (
	"crypto/rsa"
	"csrf/db"
	"csrf/db/models"
	"errors"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
)

const (
	privKeyPath = "keys/app.rsa"
	pubKeyPath = "keys/app.rsa.pub"
)

var (
	verifyKey *rsa.PublicKey
	signKey *rsa.PrivateKey
)

// Reads RSA key from files, and parses them into usable format for JWT operations
func InitDB() error{
	publicKey, err := os.ReadFile(pubKeyPath)
	if err != nil{
		return err
	}

	verifyKey, err = jwt.ParseRSAPrivateKeyFromPEM(publicKey)
	if err != nil{
		return err
	}

	privateKey, err := os.ReadFile(privKeyPath)
	if err != nil{
		return err
	}

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil{
		return err
	}

	return nil
}

func CreateNewToken(uuid, role string) (authTokenString, refreshTokenString, csrfSecret string, err error){
	csrfSecret, err = models.GenerateCSRFSecret()
	if err != nil{
		return
	}

	refreshTokenString, err = createRefreshTokenString(uuid, role, csrfSecret)
	if err != nil{
		return
	}

	authTokenString, err = createAuthTokenString(uuid, role, csrfSecret)
	if err != nil {
		return
	}
}

// validates, handles expiration by generating new tokens when neccessary
func CheckAndRefreshToken(oldAuthTokenString, oldRefreshTokenString, oldCsrfSecret string)(newAuthTokenString, newRefreshTokenString, newCsrfSecret string, err error){
	// check if CSRF is present
	if oldCsrfSecret == ""{
		log.Println("No csrf token")
		err = errors.New("unauthorized")
		return
	}

	// Parse auth token with Claims
	authToken, err := jwt.ParseWithClaims(oldAuthTokenString, &models.TokenClaims{}, func (token *jwt.Token)(interface{}, error){
		return verifyKey, nil
	})
	if err != nil && !errors.Is(err, jwt.ErrTokenExpired){
		log.Println("errors parsing the token")
		return
	}

	// Extract Claims from the token
	authTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
	if !ok{
		err = errors.New("error extracting claims from token")
		return
	}

	// Verify CSRF token matches the one in JWT
	if oldCsrfSecret != authTokenClaims.Csrf {
		log.Println("CSRF token doesn't match jwt!")
		err = errors.New("Unauthorized")
		return
	}

	// check if the Auth token is valid
	if err == nil && authToken.Valid{
		log.Println("Auth Token is valid")

		// reuse the same csrf secret
		newCsrfSecret = authTokenClaims.Csrf

		// update token if expired
		newRefreshTokneString, err = updateRefreshTokenExp(oldRefreshTokenString)
		if err != nil{
			return
		}

		// keep using the same auth token
		newAuthTokenString = oldAuthTokenString
		return
	}else{

	}
}


func createAuthTokenString(uuid, role, csrfSecret string)(authTokenString string, err error){
	// set expiration time for auth token
	authTokenExp := time.Now().Add(models.AuthTokenValidTime).Unix()

	// Create Claims for auth Token
	authClaims := models.TokenClaims{
		StandardClaims: jwt.RegisteredClaims{
			Subject:   uuid,
			ExpiresAt: jwt.NewNumericDate(time.Unix(authTokenExp, 0)),
		},
		Role: role,
		Csrf: csrfSecret,
	}

	// create new jwt with claims
	authJWT := jwt.NewWithClaims(jwt.SigningMethodRS256 ,authClaims)

	// sign the token with private key
	authTokenString, err = authJWT.SignedString(signKey)
	
	return
}

func createRefreshTokenString(uuid, role, csrfSecret string)(refreshTokenString string, err error){
	refreshTokenExp := time.Now().Add(models.RefreshTokenValidTime).Unix()

	// creates and puts the JTI in database
	refreshJTI, err := db.StoreRefreshToken()

	refreshTokenClaims := models.TokenClaims{
		StandardClaims: jwt.RegisteredClaims{
			ID: refreshJTI,
			Subject: uuid,
			ExpiresAt: refreshTokenExp,
		},
		Role: role,
		Csrf: csrfSecret,
	}

	refreshJWT := jwt.NewWithClaims(jwt.SigningMethodRS256, refreshTokenClaims)

	refreshTokenString, err = refreshJWT.SignedString(signKey)
	return
}

// if the Auth token is still valid, extends the refresh token expiry.
//  so if the user is idle they won't be logged out
func updateRefreshTokenExp(oldRefreshTokenString string)(refreshTokenString string, err error){
	refreshToken, err := jwt.ParseWithClaims(oldRefreshTokenString, &models.TokenClaims{}, func(token *jwt.Token)(interface{}, error){
		return verifyKey, nil
	})

	if err != nil{
		return	"", err
	}

	// extract claims from refresh token
	oldRefreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	
}

func updateAuthTokenString(){

}

// Extracts the JTI from refresh token and Removes it from database
func RevokeRefreshToken(){

}

func updateRefreshTokenCsrf(){

}

func GrabUUID(){

}