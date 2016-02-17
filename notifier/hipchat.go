package notifier

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
)

const (
	// HipchatDefaultEndoint is used unless custom endpoint set
	HipchatDefaultEndoint = "https://api.hipchat.com"
)

type (
	// Hipchat service sends messages to a Hipchat room
	Hipchat struct {
		Endpoint string
		RoomID   string
		Token    string
		From     string
	}
	// HipchatMessage contains a message to send to a Hipchat room
	HipchatMessage struct {
		From    string `json:"from,omitempty"`
		Message string `json:"message"`
	}
)

// NewHipchat creates a Hipchar service for notifying
func NewHipchat(config map[string]string) (*Hipchat, error) {
	h := &Hipchat{}

	for k, v := range config {
		switch k {
		case "room":
			h.RoomID = v
		case "token":
			h.Token = v
		case "from":
			h.From = v
		case "endpoint":
			h.Endpoint = v
		}
	}
	if h.RoomID == "" {
		return nil, errors.New("missing room")
	}
	if h.Token == "" {
		return nil, errors.New("missing token")
	}
	if h.From == "" {
		return nil, errors.New("missing from")
	}
	if h.Endpoint == "" {
		h.Endpoint = HipchatDefaultEndoint
	}
	fmt.Printf("Hipchat set with %#v\n", h)
	return h, nil
}

// Send writes the message
func (h *Hipchat) Send(e cloudtrail.Event) error {

	// /v2/room/{room_id_or_name}/message
	url := fmt.Sprintf("%s/v2/room/%s/notification", h.Endpoint, h.RoomID)
	message := HipchatMessage{
		From:    h.From,
		Message: aws.StringValue(e.EventId),
	}
	body, err := json.Marshal(message)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Bearer "+h.Token)
	req.Header.Add("Content-type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := ioutil.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status %d - %s\n", resp.StatusCode, respBody)
	}
	return nil

}

// Name returns the name of the service
func (h *Hipchat) Name() string {
	return "Hipchat"
}
