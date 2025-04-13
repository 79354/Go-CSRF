package main

import(
	"log"
	"csrf/db"
	"csrf/server"
	"csrf/server/middleware/myJwt"
)

var (
	host = "localhost"
	port = "9000"
)


func main(){
	// init jwt
	db.InitDB()
	
	// init server
	jwtErr := myJwt.InitJwt()
	if jwtErr != nil{
		log.Println("Error initializing the JWT!")
		log.Fatal(jwtErr)
	}
	
	// init database
	serverErr := server.StartServer(host, port)
	if serverErr != nil{
		log.Println("Error starting server")
		log.Fatal(serverErr)
	}
}