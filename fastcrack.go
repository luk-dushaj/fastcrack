package main

import (
	"bufio"
	_ "embed"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

import "github.com/yeka/zip"

//go:embed rockyou.txt
var defaultWordlist string

// checkPassword, attempts to decrypt zip password
func checkPassword(zipfilePath string, password string) bool {
	r, err := zip.OpenReader(zipfilePath)
	if err != nil {
		fmt.Printf("Error opening zip file: %v\n", err)
		os.Exit(1)
	}
	defer r.Close()

	for _, f := range r.File {
		// If the file is encrypted then set password to try
		if f.IsEncrypted() {
			f.SetPassword(password)
		}

		rc, err := f.Open()
		if err != nil {
			// The password fails for this file
			return false
		}

		_, err = io.ReadAll(rc)
		rc.Close()
		if err != nil {
			// Password is incorrect if reading fails
			return false
		}
	}

	// Returns if password is valid
	return true
}

// bruteForce, iterates through all passwords and attempts to find the correct one
func bruteForce(zipfilePath string, passwordList []string) {
	for _, password := range passwordList {
		fmt.Printf("Trying password: %s\n", password)
		if checkPassword(zipfilePath, password) {
			fmt.Printf("Password found: %s\n", password)
			return
		}
	}

	fmt.Println("Password not found in wordlist.")
}

func printHelp() {
	fmt.Println("usage: ./fastcrack [-h] zipfile (optional: wordlist)")
	fmt.Println()
	fmt.Println("Brute force zip file password.")
	fmt.Println()
	fmt.Println("positional arguments:")
	fmt.Println("  zipfile     path to zip file")
	fmt.Println("  wordlist    path to wordlist file (if no wordlist passed then program will use built in rockyou.txt)")
	fmt.Println()
	fmt.Println("options:")
	fmt.Println("  -h, --help  show this help message and exit")
}

func main() {
	// Parsing flags
	helpFlag := flag.Bool("h", false, "Show help message and exit")
	flag.Parse()

	if *helpFlag || flag.NArg() == 0 {
		printHelp()
		return
	}

	args := flag.Args()

	if len(args) < 1 || len(args) > 2 {
		printHelp()
		return
	}

	zipfilePath := args[0]
	var wordlistPath string

	// Check if wordlist is provided
	if len(args) == 2 {
		wordlistPath = args[1]
	}

	var passwordList []string

	if wordlistPath == "" {
		// Using the embedded wordlist
		fmt.Println("No wordlist specified, using built-in rockyou.txt wordlist.")

		scanner := bufio.NewScanner(strings.NewReader(defaultWordlist))
		for scanner.Scan() {
			passwordList = append(passwordList, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("Error reading built-in wordlist: %v\n", err)
		}
	} else {
		file, err := os.Open(wordlistPath)
		if err != nil {
			log.Fatalf("Error opening wordlist file: %v\n", err)
		}
		defer file.Close()

		// Reading passwords from wordlist file
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			passwordList = append(passwordList, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("Error reading wordlist file: %v\n", err)
		}
	}

	bruteForce(zipfilePath, passwordList)
}
