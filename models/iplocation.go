package models

type IPLocation struct {
	// The right side is the name of the JSON variable
	Ip          string  `json:"ip,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
	CountryName string  `json:"country_name,omitempty"`
	RegionCode  string  `json:"region_code,omitempty"`
	RegionName  string  `json:"region_name,omitempty"`
	City        string  `json:"city,omitempty"`
	Zipcode     string  `json:"zipcode,omitempty"`
	Lat         float32 `json:"latitude,omitempty"`
	Lon         float32 `json:"longitude,omitempty"`
	MetroCode   int     `json:"metro_code,omitempty"`
	AreaCode    int     `json:"area_code,omitempty"`
}
