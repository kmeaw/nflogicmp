package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"sync"
	"syscall"
	"time"

	"github.com/florianl/go-nflog/v2"
	"github.com/okzk/sdnotify"
)

const LOG_MAX_ENTRIES = 200

var SOCKET_ADDR = path.Join(os.Getenv("RUNTIME_DIRECTORY"), "http.sock")

type Log struct {
	Data map[string][]time.Time `json:"pings"`

	sync.RWMutex
}

func (l *Log) Ping(ip net.IP) {
	l.Lock()
	defer l.Unlock()

	if l.Data == nil {
		l.Data = make(map[string][]time.Time)
	}

	for len(l.Data) >= LOG_MAX_ENTRIES {
		min_key := ""
		min_value := time.Time{}

		for k, vs := range l.Data {
			if min_key == "" || vs[len(vs)-1].Before(min_value) {
				min_key = k
				min_value = vs[len(vs)-1]
			}
		}

		delete(l.Data, min_key)
	}

	slice := l.Data[ip.String()]
	for len(slice) >= LOG_MAX_ENTRIES {
		slice = slice[1:]
	}
	l.Data[ip.String()] = append(slice, time.Now())
}

func (l *Log) WriteTo(w io.Writer) error {
	enc := json.NewEncoder(w)
	l.RLock()
	defer l.RUnlock()
	return enc.Encode(l)
}

func (l *Log) ReadFrom(r io.Reader) error {
	dec := json.NewDecoder(r)
	l.Lock()
	defer l.Unlock()

	l.Data = make(map[string][]time.Time)
	return dec.Decode(r)
}

func main() {
	// Send incoming pings to nflog group 100
	// # sudo iptables -I INPUT -p icmp -m icmp --icmp-type 8 -j NFLOG --nflog-group 100

	ping_log := Log{}
	f, err := os.Open(path.Join(os.Getenv("STATE_DIRECTORY"), "state.json"))
	if nil == err {
		err = ping_log.ReadFrom(f)
		f.Close()
	}
	if err != nil && !os.IsNotExist(err) {
		log.Panicf("cannot load state: %s", err)
	}

	//Set configuration parameters
	config := nflog.Config{
		Group:       100,
		Copymode:    nflog.CopyPacket,
		ReadTimeout: 10 * time.Millisecond,
	}

	nf, err := nflog.Open(&config)
	if err != nil {
		log.Panicf("could not open nflog socket: %s", err)
	}
	defer nf.Close()

	ctx := context.Background()

	fn := func(attrs nflog.Attribute) int {
		if attrs.Payload == nil || len(*attrs.Payload) < 24 {
			return 0
		}
		switch (*attrs.Payload)[0] & 0xf0 {
		case 0x40: // IPv4
			ping_log.Ping(net.IP((*attrs.Payload)[12:16]))
		case 0x60: // IPv6
			ping_log.Ping(net.IP((*attrs.Payload)[8:24]))
		default:
			log.Printf("invalid ICMP packet: %v", attrs.Payload)
		}
		return 0
	}

	// Register your function to listen on nflog group 100
	err = nf.Register(ctx, fn)
	if err != nil {
		log.Panicf("cannot register nflog callback: %s", err)
	}

	_ = os.Remove(SOCKET_ADDR)
	old_umask := syscall.Umask(0007)
	listener, err := net.Listen("unix", SOCKET_ADDR)
	syscall.Umask(old_umask)

	if err != nil {
		log.Panicf("cannot listen %s: %s", SOCKET_ADDR, err)
	}

	srv := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	http.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		ping_log.WriteTo(w)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		ping_log.RLock()
		defer ping_log.RUnlock()

		for k, vs := range ping_log.Data {
			fmt.Fprintf(w, "%s:\n", k)
			for _, v := range vs {
				fmt.Fprintf(w, "\t%f %s\n", float64(v.UnixNano())*1e-9, v.String())
			}
			fmt.Fprintf(w, "\n")
		}
	})

	go func() {
		log.Fatal(srv.Serve(listener))
	}()

	// Save the log
	go func(C <-chan time.Time) {
		for range C {
			f, err := os.OpenFile(path.Join(os.Getenv("STATE_DIRECTORY"), "/state.json"), os.O_TRUNC|os.O_CREATE, 0666)
			if nil == err {
				err = ping_log.WriteTo(f)
				f.Close()
			}

			if err != nil {
				log.Printf("cannot store state: %s", err)
			}
		}
	}(time.NewTicker(15 * time.Second).C)

	sdnotify.Ready()

	// Block till the context expires
	<-ctx.Done()
}
