package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/billhathaway/cloudtail/notifier"
)

type (
	// Stash is used to filter events
	Stash struct {
		EventName    string        `json:"event_name,omitempty"`
		Username     string        `json:"user_name,omitempty"`
		TTL          time.Duration `json:"ttl,omitempty"`
		Expiration   time.Time     `json:"expiration,omitempty"`
		Regex        string        `json:"regex,omitempty"`
		ResourceName string        `json:"resource_name,omitempty"`
		ResourceType string        `json:"resource_type,omitempty"`
		Description  string        `json:"description,omitempty"`
		Destinations []string      `json:"destinations,omitempty"`
		// re           *regexp.Regexp
	}
	// Controller manages the notifier
	Controller struct {
		stashes   map[int]Stash
		debug     bool
		notifiers []Notifiers
		mu        sync.RWMutex
		log       *log.Logger
	}
	// Config holds the configuration for the notifier
	Config struct {
		Listen    string `json:"listen"`
		Debug     bool   `json:"debug"`
		Notifiers map[string]map[string]string
		Stashes   []Stash
	}
	// Notifiers are used to send events
	Notifiers interface {
		Send(cloudtrail.Event) error
		Name() string
	}
)

// discard returns true if an event should not be forwarded
// TODO logic for most fields
func (s *Stash) discard(event cloudtrail.Event, dest string) bool {
	if s.EventName != "" && s.EventName == aws.StringValue(event.EventName) {
		return true
	}
	if s.Username != "" && s.Username == aws.StringValue(event.Username) {
		return true
	}
	return false
}

func (c *Controller) getStashes(w http.ResponseWriter, r http.Request) {

	stashes := make(map[int]Stash)
	c.mu.RLock()
	for i, stash := range c.stashes {
		stashes[i] = stash
	}
	c.mu.RUnlock()

}
func (c *Controller) processEvent(event cloudtrail.Event) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, sv := range c.notifiers {
		name := sv.Name()
		var discard bool
		for stashID, st := range c.stashes {
			if st.discard(event, name) {
				discard = true
				c.log.Printf("fn=processEvent action=match stash=%d\n", stashID)
				break
			} else {
				c.log.Printf("fn=processEvent action=noMatch stash=%d\n", stashID)
			}
		}
		if discard {
			c.log.Printf("fn=processEvent action=discard dest=%s id=%s\n", name, aws.StringValue(event.EventId))
			continue
		}
		err := sv.Send(event)
		if err != nil {
			c.log.Printf("fn=processEvent action=send dest=%s id=%s status=error err=%v\n", name, aws.StringValue(event.EventId), err)
			continue
		}
		c.log.Printf("fn=processEvent action=send dest=%s id=%s status=ok\n", name, aws.StringValue(event.EventId))
	}
}

// testHandler is sent a CloudTrail event and processes it
func (c *Controller) testHandler(w http.ResponseWriter, r *http.Request) {
	var event cloudtrail.Event
	err := json.NewDecoder(r.Body).Decode(&event)
	if err != nil {
		c.log.Printf("fn=testHandler event=decodeEvent err=%q\n", err)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, err.Error())
		return
	}
	c.processEvent(event)
}

// stashHandler adds a new stash
func (c *Controller) stashPOSTHandler(w http.ResponseWriter, r *http.Request) {
	var s Stash
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

func (c *Controller) addStash(s Stash) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	stashes := len(c.stashes)
	nextStash := stashes + 1
	c.stashes[nextStash] = s
	return nextStash
}

func (c *Controller) addNotifier(s Notifiers) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.notifiers = append(c.notifiers, s)
}

// Load reads a config and builds a controller
func Load(r io.Reader) (*Controller, error) {
	var config Config
	err := json.NewDecoder(r).Decode(&config)
	if err != nil {
		return nil, err
	}
	controller := New()
	for sname, sconfig := range config.Notifiers {
		switch sname {
		case "stdout":
			controller.addNotifier(&notifier.Stdout{})
		case "hipchat":
			hc, err := notifier.NewHipchat(sconfig)
			if err != nil {
				return nil, fmt.Errorf("could not create Hipchat notifier: %s", err)
			}
			controller.addNotifier(hc)
		default:
			return nil, fmt.Errorf("unknown notifier type %q", sname)
		}
	}
	return controller, nil
}

// New creates a new Controller
func New() *Controller {
	c := &Controller{
		stashes:   make(map[int]Stash),
		notifiers: make([]Notifiers, 0),
		log:       log.New(os.Stderr, "cloudtail ", log.LstdFlags),
	}
	return c
}

func main() {
	port := flag.String("p", "8888", "listen port")
	config := flag.String("f", "", "config file")
	var c *Controller
	flag.Parse()
	if *config != "" {
		fh, err := os.Open(*config)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		c, err = Load(fh)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	} else {
		c = New()
	}
	http.HandleFunc("/stash", c.stashPOSTHandler)
	http.HandleFunc("/test", c.testHandler)
	c.log.Printf("Listening on port %s\n", *port)
	c.log.Fatalln(http.ListenAndServe(":"+*port, nil))

}
