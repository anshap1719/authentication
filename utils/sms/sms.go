package sms

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

var authKey = ""

func SendPhoneVerificationOTP(country string, phone string, otp string) error {
	url := "https://api.msg91.com/api/v2/sendsms"

	var payload = map[string]interface{}{
		"sender":  "GALLER",
		"route":   "4",
		"country": country,
		"sms": []map[string]interface{}{
			{
				"message": "Your Phone Verification Code Is " + otp + " Valid For The Next 2 Minutes.",
				"to":      []string{phone},
			},
		},
	}

	byt, _ := json.Marshal(&payload)

	buf := bytes.NewBuffer(byt)

	req, err := http.NewRequest("POST", url, buf)
	if err != nil {
		fmt.Println(err)
		return err
	}

	req.Header.Add("authkey", authKey)
	req.Header.Add("content-type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.Status != "200" {
		var bod map[string]interface{}

		json.NewDecoder(resp.Body).Decode(&bod)

		fmt.Println(bod)
		return err
	}

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
