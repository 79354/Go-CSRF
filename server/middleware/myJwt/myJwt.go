package myJwt

import (
	"crypto/rsa"
	"csrf/db"
	"csrf/db/models"
	"errors"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
	}else if errros.Is(err, jwt.ErrTokenExpired){
		// Handle expired auth token
		log.Println("Auth token is expired")

		// create new auth token and CSRF secret
		newAuthTokenString, newCsrfSecret := updateAuthTokenString(oldRefreshTokenString, oldAuthTokenString)
		if err != nil{
			return
		}

		// update refresh token expiration
		newRefreshTokenString, err = updateRefreshTokenExp(oldRefreshTokenString)
		if err != nil{
			return
		}

		// update refresh token with new newCsrfSecret
		newRefreshTokenString, err = updateRefreshTokenCsrf(newRefreshTokenString, newCsrfSecret)
		return
	} else{
		log.Println("error in auth token")
		err = errors.New("error in auth token")
		return
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
	if !ok {
		return "", errors.New("error extracting claims from refresh token")
	}

	// calculate new expiration time
	refreshTokenExp := time.Now().Add(models.RefreshTokenValidTime).Unix()

	refreshClaims := models.TokenClaims{
		StandardClaims: jwt.RegisteredClaims{
			ID: oldRefreshTokenClaims.StandardClaims.ID,
			Subject: oldRefreshTokenString.StandardClaims.Subject,
			ExpiresAt: jwt.NewNumericDate(time.Unix(refreshTokenExp, 0)),
		},
		Role: oldRefreshTokenClaims.Role,
		Csrf: oldRefreshTokenClaims.Csrf,
	}

	refreshJWT := jwt.NewWithClaims(jwt.SigningMethodRS256, refreshClaims)
	refreshTokenString, err = refreshJWT.SignedString(signKey)
	return
}

func updateAuthTokenString(refreshTokenString string, oldAuthTokenString string)(newAuthTokenString, csrfSecret string, err error){
	refreshTokenString, err := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims, func(token jwt.Token)(interface{}, error){
		verifyKey, nil
	})

	if err != nil{
		return "", "", err
	}

	// Extract claims from refresh token
	refreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		err = errors.New("Error extracting claims from refresh token")
		return
	}

	// check if the refresh Token is valid in database
	if db.CheckRefreshToken(refreshTokenClaims.StandardClaims.ID){
		// verify the token validity (not expired)
		if refreshToken.Valid{
			authToken, _ := jwt.ParseWithClaims(oldAuthTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
				return verifyKey, nil
			})

			oldAuthTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
			if !ok{
				err = errors.New("Error extracting claims from auth token")
				return
			}

			// Generate new CSRF secret
			csrfSecret, err = models.GenerateCSRFSecret()
			if err != nil{
				return
			}

			newAuthTokenString, err := createAuthTokenString(oldAuthTokenString.StandardClaims.Subject, oldAuthTokenClaims.Role, csrfSecret)
			return
		}else {
			log.Println("Refresh token has expired!")
			
			// Delete the expired refresh token from database
			db.DeleteRefreshToken(refreshTokenClaims.StandardClaims.ID)
			
			err = errors.New("Unauthorized")
			return
		}
	}else {
		log.Println("Refresh token has been revoked!")
		err = errors.New("Unauthorized")
		return
	}
}

// Extracts the JTI from refresh token and Removes it from database
func RevokeRefreshToken(refreshTokenString string) error{
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims{}, func(token *jwt.Token)(interface{}, errors){
		return verifyKey, nil
	})

	if err != nil {
		return errors.New("could not parse refresh token with claims")
	}

	refreshClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok{
		return errors.New("could not extract claims from refresh token")
	}

	db.DeleteRefreshToken(refreshToken.Claims.StandardClaims.ID)
	return nil
}

func updateRefreshTokenCsrf(oldRefreshTokenString string, newCSRF string)(refreshTokenString string,  error){
	refreshToken, err := jwt.ParseWithClaims(oldRefreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	
	if err != nil {
		return "", err
	}

	oldRefreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		return "", errors.New("Error extracting claims from refresh token")
	}

	refreshClaims := models.TokenClaims{
		StandardClaims: jwt.RegisteredClaims{
			ID: oldRefreshTokenClaims.StandardClaims.ID,
			Subject: oldRefreshTokenClaims.StandardClaims.Subject,
			ExpiresAt: oldRefreshTokenClaims.StandardClaims.ExpiresAt,
		},

		Role: role,
		Csrf: newCSRF,
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodRS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(signKey)
	return
}

func GrabUUID(authTokenString string) (string, error){
	authToken, _ := jwt.ParseWithClaims(authTokenString, &models.TokenClaims, func(token jwt.Token)(interface{}, error){
		return verifyKey, nil
	})

	authTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
	if !ok {
		return "", errors.New("error extracting claims from auth token")
	}

	return authTokenClaims.StandardClaims.Subject, nil
}