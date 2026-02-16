package core

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	g "github.com/s0md3v/smap/internal/global"
	"golang.org/x/net/proxy"
)

var client *http.Client

func InitClient() {
	transport := &http.Transport{
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if g.ProxyAddr != "" {
		dialer, err := proxy.SOCKS5("tcp", g.ProxyAddr, nil, proxy.Direct)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create SOCKS5 dialer: %v\n", err)
			os.Exit(1)
		}
		transport.Dial = dialer.Dial
		fmt.Fprintf(os.Stderr, "Using SOCKS5 proxy: %s\n", g.ProxyAddr)
	} else {
		transport.Dial = (&net.Dialer{Timeout: 8 * time.Second}).Dial
	}
	client = &http.Client{Transport: transport}
}

func Query(ip string) []byte {
	url := "https://internetdb.shodan.io/" + ip
	req, err := http.NewRequest("GET", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return []byte{}
	}
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte{}
	}
	req.Close = true
	defer resp.Body.Close()
	if strings.HasPrefix(string(content), `{"error":`) {
		fmt.Println("Warning: Response starts with \"{\"error\":\", this may indicate an error.")
		return []byte{}
	}

	return content
}
