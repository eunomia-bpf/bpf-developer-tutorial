package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
)

var http_body []byte

func handler(w http.ResponseWriter, r *http.Request) {
	w.Write(http_body)
}

func main() {
	args := os.Args
	if len(args) > 1 {
		body_len, _ := strconv.ParseInt(args[1], 10, 64)
		http_body = make([]byte, body_len)
		rand.Read(http_body)
		fmt.Println("Body set to", body_len, "bytes of random stuff")
	} else {
		http_body = []byte("Hello,World!")
	}
	http.HandleFunc("/", handler)
	fmt.Println("Server started!")
	err := http.ListenAndServe(":447", nil)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
