package main

import (
	"net/http"
	"sync"
	"time"
)

type Client struct {
	*http.Client
	isInitialized bool
}

var pool = sync.Pool{
	New: func() interface{} {
		return &Client{&http.Client{}, false}
	},
}

func GetClient(timeout time.Duration) *Client {
	c := pool.Get().(*Client)
	if !c.isInitialized {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.MaxIdleConns = 100
		t.MaxConnsPerHost = 100
		t.MaxIdleConnsPerHost = 100
		t.TLSClientConfig.InsecureSkipVerify = true
		c.Transport = t
		c.isInitialized = true
	}
	c.Timeout = timeout
	return c
}

func ReleaseClient(client *Client) {
	pool.Put(client)
}

func Request(target Target, timeout time.Duration) (int, error) {
	c := GetClient(timeout)
	defer ReleaseClient(c)

	req, err := http.NewRequest("GET", target.Host, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0")

	if target.HeaderKey != "" {
		req.Header.Set(target.HeaderKey, target.HeaderValue)
	}

	var resp *http.Response
	resp, err = c.Do(req)
	if err != nil {
		return 0, err
	}
	return resp.StatusCode, nil
}
