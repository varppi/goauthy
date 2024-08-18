package utils

import "golang.org/x/crypto/bcrypt"

func HashPassword(password string) (string, error) {
	var passwordBytes = []byte(password)
	hashedPasswordBytes, err := bcrypt.
		GenerateFromPassword(passwordBytes, 10)
	return string(hashedPasswordBytes), err
}
