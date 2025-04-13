package myJwt

import (
	"crypto/rsa"
	"errors"
	"csrf/db"
	"csrf/db/models"
	jwt "github.com/golang-jwt/jwt"
	"io"
	"log"
	"time"
)

const (
	privKeyPath = "keys/app.rsa"
	pubKeyPath = "keys/app.rsa.pub"
)

var (
	verify
)