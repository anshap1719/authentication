package sms

import (
	"crypto/rand"
	"fmt"
	"io"
)

func SendPhoneVerificationOTP(country string, phone string, otp string) error {
	// Send OTP Using A Service
	// @TODO: Implement Service Of Choice
	fmt.Println(country, phone, otp)
	return nil
}

func GenerateOTP() string {
	return EncodeToString(6)
}

func EncodeToString(max int) string {
	b := make([]byte, max)
	n, err := io.ReadAtLeast(rand.Reader, b, max)
	if n != max {
		panic(err)
	}
	for i := 0; i < len(b); i++ {
		b[i] = table[int(b[i])%len(table)]
	}
	return string(b)
}

var table = [...]byte{'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'}
