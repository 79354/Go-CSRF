// Provides in-memory storage for users and refresh tokens
// Handles user authentication and token management
package db

import (
	"csrf/db/models"
	"csrf/randomstrings"
	"errors"
	"log"

	"golang.org/x/crypto/bcrypt"
)

// key: uuid, database of user
var users = map[string]models.User{}

// key: JTI (json token identifier)
// value could be used as valid, revoked

var refreshTokens map[string]string

func InitDB() {
	refreshTokens = make(map[string]string)
}

// password is hashed
func StoreUser(username string, password string, role string) (uuid string, err error) {
	uuid, err = randomstrings.GenerateRandomString(32)
	if err != nil{
		return "", err
	}

	// check to make sure uuid is unique
	u := models.User{}
	for u != users[uuid] {
		uuid, err = randomstrings.GenerateRandomString(32)
		if err != nil{
			return "", err
		}
	}

	// generate the bcrypt password hash
	hash, hashErr := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	passwordHash := string(hash[:])
	if hashErr != nil{
		err = hashErr
		return
	}

	users[uuid] = models.User{username, passwordHash, role}

	return uuid, err
}

func DeleteUser(uuid string) {
	delete(users, uuid) // (value, key)
}

func FetchUserById(uuid string) (models.User, error) {
	u := users[uuid]
	blankUser := models.User{}

	if blankUser != u {
		return u, nil
	}else {
		return u, errors.New("User not found that matches given uui")
	}
}

func FetchUserByUsername(username string) (models.User, string, error) {

	for k, v := range users {
		if v.Username == username {
			return v, k, nil
		}
	}

	return models.User{}, "", errors.New("User not found that matches given username")
}

func StoreRefreshToken() (jti string, err error){
	jti, err = randomstrings.GenerateRandomString(32)
	if err != nil {
		return jti, err
	}

	// check to make sure jti is unique
	for refreshTokens[jti] != ""{
		jti, err = randomstrings.GenerateRandomString(32)
		if err != nil{
			return jti, err
		}
	}

	refreshTokens[jti] = "valid"
	return jti, err
}

func DeleteRefreshToken(jti string){
	delete(refreshTokens, jti)
}

func CheckRefreshToken(jti string) bool {
	if refreshTokens[jti] != ""{
		return true
	}
	return false
}

func LogUserIn(username string, password string) (models.User, string, error){
	user, uuid, userErr := FetchUserByUsername(username)
	log.Println(user, uuid, userErr)

	if userErr != nil{
		return models.User{}, "", userErr
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	
	return user, uuid, err
}