package main

import (
	"fmt"
	"bufio"
	"crypto/tls"
	"sync"
	"net/url"
	"flag"
	"net"
	"strings"
	"net/http"
	"time"
	"os"
	"io"

	"github.com/pmezard/go-difflib/difflib"
	"golang.org/x/net/html"
)

type Response struct {
    pageStructure []string
    headers  http.Header
	status int
}

var urlStatusCodeMap = make(map[string]int) // {url: 200, url1: 300}
var Map2xx = make(map[string]*Response) // {url: response} code = 2xx
var Map3xx = make(map[string]*Response) // {url: response} code = 3xx
var Map4xx = make(map[string]*Response) // {url: response} code = 4xx
var Mapxx = make(map[string]*Response) // {url: response} other code
var MAX_UNIQUES = 3 // 1 means remove any duplicate, 2 means we will 2 uniques subs. It prefers https over http

var uniques []string

var Concurrency int
var ProxyUrl string // proxy url 

func main() {
	var domains []string
	// Concurrency needed
	flag.IntVar(&Concurrency, "c", 30, "set the concurrency level (split equally between HTTPS and HTTP requests)")
	// proxy url
	flag.StringVar(&ProxyUrl, "x", "", "Proxy url in format-> http://127.0.0.1:8080")

	flag.Parse()

	// Read domains from stdin
	s := bufio.NewScanner(os.Stdin)
	for s.Scan() {
		domains = append(domains, s.Text())
	}
	// start := time.Now()
	Dedupe(domains, Concurrency);
	// elapsed := time.Since(start)
	// fmt.Println(elapsed)
}


func Dedupe(domains []string, concurrency int) {

	urlChannel := make(chan string)
	
	var mainWG = &sync.WaitGroup{}
	var client = getHttpClient(ProxyUrl)
	var headers = []string{"User-Agent: Mozilla", "X-Forwarded-For: 127.0.0.1"}
	mutex := &sync.RWMutex{}
	var map_keys []string;
	
	for i:=0; i < concurrency; i++ {
		mainWG.Add(1);

		go func () {
			for url := range urlChannel {
				
				var statusRounded int
				response, _ := HttpRequest(client, url, "GET", headers)
				statusRounded = (response.status / 100) * 100

				mutex.Lock()
				if statusRounded == 200 {
					urlStatusCodeMap[url] = 200
					Map2xx[url] = response

				} else if statusRounded == 300 {
					urlStatusCodeMap[url] = 300
					Map3xx[url] = response

				} else if statusRounded == 400 {
					urlStatusCodeMap[url] = 400
					Map4xx[url] = response

				} else {
					urlStatusCodeMap[url] = 0
					Mapxx[url] = response
				}
				mutex.Unlock()
			}
			mainWG.Done();
		}();
	}

	for _, domain := range (domains) {
		if domain != "" {
			urlChannel <- domain
		}
	}

	close(urlChannel)
	mainWG.Wait()

	// Status code 2xx's
	// Group similar 200
	// prefer https
	map_keys = MapKeys(Map2xx)
	
	for i:=0; i < len(map_keys); i++ {
		curr_url := map_keys[i]
		curr_res, found := Map2xx[curr_url]
		
		if found == false {
			continue
		}
		var matches = make([]string, 0)

		for j:=i+1; j < len(map_keys); j++ { 
			other_url := map_keys[j]
			other_res, found := Map2xx[other_url]
			if found == false {
				continue
			}

			if len(matches) < MAX_UNIQUES {
				if (GetSimilarity(curr_res.pageStructure, other_res.pageStructure) > 0.96 ) {
					matches = append(matches, other_url)
					delete(Map2xx, other_url)
				}
			} else if len(matches) >= MAX_UNIQUES && len(matches) < MAX_UNIQUES + 2 { // Add 2 more https only
				u, _ := url.Parse(other_url)
				if u.Scheme == "https" {
					if (GetSimilarity(curr_res.pageStructure, other_res.pageStructure) > 0.96 ) {
						matches = append(matches, other_url)
						delete(Map2xx, other_url)
					}
				}
				
			} else {
				break
			}
		}
		if len(matches) < MAX_UNIQUES {
			matches = append(matches, curr_url)
		}
		delete(Map2xx, curr_url)
		uniques = append(uniques, matches...)
	}


	// status 3xx

	// status 4xx
	map_keys = MapKeys(Map4xx)

	for i:=0; i < len(map_keys); i++ {
		curr_url := map_keys[i]
		curr_res, found := Map4xx[curr_url]
		
		if found == false {
			continue
		}
		var matches = make([]string, 0)
	
		for j:=i+1; j < len(map_keys); j++ { 
			other_url := map_keys[j]
			other_res, found := Map4xx[other_url]
			if found == false {
				continue
			}
	
			if len(matches) < MAX_UNIQUES {
				if (GetSimilarity(curr_res.pageStructure, other_res.pageStructure) > 0.97 ) {
					matches = append(matches, other_url)
					delete(Map4xx, other_url)
				}
			} else if len(matches) >= MAX_UNIQUES && len(matches) < MAX_UNIQUES + 2 { // Add 2 more https only
				u, _ := url.Parse(other_url)
				if u.Scheme == "https" {
					if (GetSimilarity(curr_res.pageStructure, other_res.pageStructure) > 0.97 ) {
						matches = append(matches, other_url)
						delete(Map4xx, other_url)
					}
				}
				
			} else {
				break
			}
		}
		if len(matches) < MAX_UNIQUES {
			matches = append(matches, curr_url)
		}
		delete(Map4xx, curr_url)
		uniques = append(uniques, matches...)
	}
	
	// status 500, 1xx 
	map_keys = MapKeys(Mapxx)

	for i:=0; i < len(map_keys); i++ {
		curr_url := map_keys[i]
		curr_res, found := Mapxx[curr_url]
		
		if found == false {
			continue
		}
		var matches = make([]string, 0)
	
		for j:=i+1; j < len(map_keys); j++ { 
			other_url := map_keys[j]
			other_res, found := Mapxx[other_url]
			if found == false {
				continue
			}
	
			if len(matches) < MAX_UNIQUES + 5 {
				if (GetSimilarity(curr_res.pageStructure, other_res.pageStructure) > 0.97 ) {
					matches = append(matches, other_url)
					delete(Mapxx, other_url)
				}
			} else if len(matches) >= MAX_UNIQUES && len(matches) < MAX_UNIQUES + 4 { // Add 2 more https only
				u, _ := url.Parse(other_url)
				if u.Scheme == "https" {
					if (GetSimilarity(curr_res.pageStructure, other_res.pageStructure) > 0.97 ) {
						matches = append(matches, other_url)
						delete(Mapxx, other_url)
					}
				}
			} else {
				break
			}
		}
		if len(matches) < MAX_UNIQUES {
			matches = append(matches, curr_url)
		}
		delete(Mapxx, curr_url)
		uniques = append(uniques, matches...)
	}

	for domain, _ := range(uniques) {
		fmt.Println(domain)
	}
	
}


func getHttpClient(ProxyUrl string) *http.Client {
	var tr *http.Transport;
	var timeout = time.Duration(10000 * 1000000) // 10 seconds

	if ProxyUrl != "" {
		if proxyUrlParsed, err := url.Parse(ProxyUrl); err != nil || proxyUrlParsed.Scheme != "http" {
			fmt.Println("Invalid proxy url. Use format - http://127.0.0.1:8080 ")
			fmt.Println(err)
			os.Exit(1)

		} else {
			tr = &http.Transport{
				MaxIdleConns:      30,
				IdleConnTimeout:   time.Second,
				DisableKeepAlives: true,
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
				Proxy: http.ProxyURL(proxyUrlParsed),
				DialContext: (&net.Dialer{
					Timeout:   timeout,
					KeepAlive: time.Second,
				}).DialContext,
			}
		}
	} else {
		tr = &http.Transport{
			MaxIdleConns:      30,
			IdleConnTimeout:   time.Second,
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: time.Second,
			}).DialContext,
		}
	}

	re := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: re,
		Timeout:       timeout,
	}

	return client;
}

func GetSimilarity(a, b []string) float64 {
	matcher := difflib.NewMatcher(a, b)
	return matcher.Ratio()
}

func HttpRequest(client *http.Client, domain string, method string, headers []string) (*Response, error) {
	req, err := http.NewRequest(method, domain, nil)
	var emptyResponse = Response{};

	if err != nil {
		return &emptyResponse, err
	}

	for _, header := range(headers) {
		temp := strings.Split(header, ":")
		if temp[0] == "Host" {
			req.Host = strings.TrimSpace(temp[1])
		} else {
			req.Header.Set(strings.TrimSpace(temp[0]), strings.TrimSpace(temp[1]))
		}
	}

	req.Header.Add("Connection", "close")
	req.Close = true

	resp, err := client.Do(req)

	if err != nil {
		return &emptyResponse, err
	}
	defer resp.Body.Close()

	htmlTokens, err := GetPageStructure(resp.Body)
	if err != nil {
		return &emptyResponse, err
	}
	response := Response{headers: resp.Header, status: resp.StatusCode, pageStructure: htmlTokens}

	return &response, nil
}

func GetPageStructure(body io.Reader) ([]string, error) {
	var structure []string
	z := html.NewTokenizer(body)
	for {
		tt := z.Next()
		token := z.Token()
		switch tt {
		case html.ErrorToken:
			return structure, nil
		case html.StartTagToken:
			structure = append(structure, token.Data)
			for _, attr := range token.Attr {
				if attr.Key != "id" {
					continue
				}
				structure = append(structure, fmt.Sprintf("#%s", attr.Val))
				break
			}
		}
	}
}

func MapKeys(keymap map[string]*Response) []string {

	var keys = make([]string, len(keymap))
	var i int32 = 0

	for val, _ := range(keymap) {
		keys[i] = val
		i += 1
	}

	return keys
}