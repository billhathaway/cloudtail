package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
)

type (
	stash struct {
		EventName string `json:",omitempty"`
		Username  string `json:",omitempty"`
		// TTL       time.Duration `json:"omitempty"`
		// Regex        string        `json:"omitempty"`
		// ResourceName string        `json:"omitempty"`
		// ResourceType string        `json:"omitempty"`
		// Comment      string        `json:"omitempty"`
		Destinations []string `json:",omitempty"`
		// re           *regexp.Regexp
	}
	// Controller manages the service
	Controller struct {
		stashes  map[int]stash
		services []service
		mu       sync.RWMutex
		log      *log.Logger
	}
	service interface {
		Send(cloudtrail.Event)
		Name() string
	}
	stdoutService struct {
		enc *json.Encoder
	}
)

func (s *stdoutService) Send(e cloudtrail.Event) {
	if s.enc == nil {
		s.enc = json.NewEncoder(os.Stdout)
	}
	s.enc.Encode(e)
}

func (s *stdoutService) Name() string {
	return "stdout"
}

// discard returns true if an event should not be forwarded
// TODO logic for most fields
func (s *stash) discard(event cloudtrail.Event, dest string) bool {
	if s.EventName != "" && s.EventName == aws.StringValue(event.EventName) {
		return true
	}
	if s.Username != "" && s.Username == aws.StringValue(event.Username) {
		return true
	}
	return false
}

// testHandler is sent CloudTrail event and processes it
func (c *Controller) testHandler(w http.ResponseWriter, r *http.Request) {
	var event cloudtrail.Event
	err := json.NewDecoder(r.Body).Decode(&event)
	if err != nil {
		c.log.Printf("fn=testHandler event=decodeEvent err=%q\n", err)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, err.Error())
		return
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, sv := range c.services {
		name := sv.Name()
		var discard bool
		for stashID, st := range c.stashes {
			if st.discard(event, name) {
				discard = true
				c.log.Printf("fn=testHandler action=match stash=%d\n", stashID)
				break
			} else {
				c.log.Printf("fn=testHandler action=noMatch stash=%d\n", stashID)
			}
		}
		if !discard {
			c.log.Printf("fn=testHandler action=send dest=%s id=%s\n", name, aws.StringValue(event.EventId))
			sv.Send(event)
		} else {
			c.log.Printf("fn=testHandler action=discard dest=%s id=%s\n", name, aws.StringValue(event.EventId))
		}
	}
}

// stashHandler adds a new stash
func (c *Controller) stashPOSTHandler(w http.ResponseWriter, r *http.Request) {
	var s stash
	err := json.NewDecoder(r.Body).Decode(&s)
	if err != nil {
		c.log.Printf("fn=stashPOSTHandler event=decodeStash err=%q\n", err)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, err.Error())
		return
	}
	id := c.addStash(s)
	fmt.Fprintf(w, "stash %d added\n", id)
	c.log.Printf("fn=stashPOSTHandler event=addStash id=%d\n", id)
}

func (c *Controller) addStash(s stash) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	stashes := len(c.stashes)
	nextStash := stashes + 1
	c.stashes[nextStash] = s
	return nextStash
}

func (c *Controller) addService(s service) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.services = append(c.services, s)
}

// New creates a new Controller
func New() *Controller {
	c := &Controller{
		stashes:  make(map[int]stash),
		services: make([]service, 0),
		log:      log.New(os.Stderr, "cloudtail ", log.LstdFlags),
	}
	return c
}

func main() {
	c := New()
	stdout := &stdoutService{}
	c.addService(stdout)
	http.HandleFunc("/stash", c.stashPOSTHandler)
	http.HandleFunc("/test", c.testHandler)
	port := flag.String("p", "8888", "listen port")
	flag.Parse()
	c.log.Printf("Listening on port %s\n", *port)
	c.log.Fatalln(http.ListenAndServe(":"+*port, nil))

}
