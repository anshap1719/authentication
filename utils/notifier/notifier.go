package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

func NotifySlack (payload map[string]interface{}) {
	client := http.DefaultClient

	buf := bytes.NewBuffer(nil)

	if err := json.NewEncoder(buf).Encode(&payload); err != nil {
		fmt.Println(err)
		return
	}

	req, err := http.NewRequest("POST", "", buf); if err != nil {
		fmt.Println(err)
		return
	}

	_, err = client.Do(req); if err != nil {
		fmt.Println(err)
		return
	}
}
