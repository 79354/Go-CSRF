package middleware

import (
	"net/http"
	"log"
	"time"
	"strings"
	"csrf/middleware/myJwt"
	"csrf/db"

	"github.com/justinas/alice"
)

func NewHandler() http.Handler{
	return alice.New(recoverHandler, authHandler).ThenFunc(logicHandler)
}

func recoverHandler(next http.Handler) http.Handler{
	fn := func(w http.ResponseWriter, r *http.Request){
		defer func(){
			if err := recover(); err != nil{
				log.Panic("Recovered! Panic:%+v", err)
				http.Error(w, http.StatusText(500), 500)
			}
		}()
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func authHandler(next http.Handler) http.Handler{
	fn := func(w http.ResponseWriter, r *http.Request){
		switch r.URL.Path{
		case "/restricted", "/logout", "/deleteUser":	// check for jwt
		default: 
		}
	}
}

func logicHandler(w http.ResponseWriter, r *http.Request){
	switch r.URL.PATH{
	case "/restricted":
	case "login":
		switch r.Method{
			case "GET":
			case "POST":
			default:
		}

	case "/register":
		switch r.Method{
			case "GET":	
			case "POST":
			default:
		}
	case "/logout":
	case "/deleteUser": 
	default:

	}
}
// revokes cookie
func nullifyTokenCookies(w *http.ResponseWriter, r *http.Request){
	authCookie = http.Cookie{
		Name:"AuthToken",
		Value:"",
		Expires:time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}

	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name:"RefreshToken",
		Value:"",
		Expires: time.Now().Add(-1000*time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(*w, &refreshCookie)
}

func setAuthAndRefreshCookies(w *http.ResponseWriter, authTokenString string, refreshTokenString string){
	authCookie := http.Cookie{
		Name: "AuthToken",
		Value: authTokenString,
		HttpOnly: true,
	}

	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name: "RefreshToken",
		Value: refreshTokenString,
		HttpOnly: true,
	}

	http.SetCookie(*w, &refreshCookie)
}

func grabCsrfFromReq(r *http.Request) string{
	
}