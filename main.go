package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

type PassData struct {
	Title    string `json:"title"`
	Login    string `json:"login"`
	Password string `json:"password"`
}

func main() {
	if len(os.Args) < 4 {
		fmt.Println("not enough arguments")
	}

	pd := PassData{
		Title:    os.Args[1],
		Login:    os.Args[2],
		Password: os.Args[3],
	}

	f, err := os.Create("passman_data.json")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	if err := json.NewEncoder(f).
		Encode(&pd); err != nil {
		log.Fatal(err)
	}

	fmt.Println("saved")
}
