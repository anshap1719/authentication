package iplocation

import (
	"encoding/json"
	"github.com/anshap1719/authentication/models"
	"net/http"
)

func GetLocationByIp(ipaddress string) (models.IPLocation, error) {
	url := "https://freegeoip.app/json/" + ipaddress

	req, _ := http.NewRequest("GET", url, nil)

	req.Header.Add("accept", "application/json")
	req.Header.Add("content-type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return models.IPLocation{}, err
	}

	defer res.Body.Close()
	var location models.IPLocation

	if err := json.NewDecoder(res.Body).Decode(&location); err != nil {
		return models.IPLocation{}, err
	}

	return location, nil
}
