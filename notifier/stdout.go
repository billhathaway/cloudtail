package notifier

import (
	"encoding/json"
	"os"

	"github.com/aws/aws-sdk-go/service/cloudtrail"
)

type (
	// Stdout service writes messages to os.Stdout
	Stdout struct {
		enc *json.Encoder
	}
)

// Send writes the message
func (s *Stdout) Send(e cloudtrail.Event) error {
	if s.enc == nil {
		s.enc = json.NewEncoder(os.Stdout)
	}
	return s.enc.Encode(e)
}

// Name returns the name of the service
func (s *Stdout) Name() string {
	return "stdout"
}
