package main

import (
	// "encoding/base64"
	"fmt"
	"bufio"
	"crypto/tls"
	"sync"
	"net/url"
	"flag"
	"net"
	"errors"
	"strings"
	"net/http"
	"time"
	"os"
	"io/ioutil"
	"io"

	"github.com/pmezard/go-difflib/difflib"
	"golang.org/x/net/html"
)


var SiteSourcecodeMap = make(map[string][]string)
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
	var headers = []string{}
	mutex := &sync.RWMutex{}
	
	for i:=0; i < Concurrency; i++ {
		mainWG.Add(1);

		go func () {
			for url := range urlChannel {

				if found, _ := SiteSourcecodeMap[url]; found != nil {
					continue;
				}
				mutex.RLock()
				var totalDomainsInMap = len(SiteSourcecodeMap)
				mutex.RUnlock()

				currentResponseBody, err := HttpRequest(client, url, "GET", headers);

				if totalDomainsInMap == 0 || err != nil {
					mutex.Lock()
					SiteSourcecodeMap[url] = currentResponseBody;
					mutex.Unlock()
				} else {
					mutex.Lock()
					for url, otherResponse := range(SiteSourcecodeMap) {
						if matchRatio := GetSimilarity(currentResponseBody, otherResponse); matchRatio > 0.95 {
							// this is almost same
						} else {
							SiteSourcecodeMap[url] = currentResponseBody;
						}
					}
					mutex.Unlock()
				}
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

	for domain, _ := range(SiteSourcecodeMap) {
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

func HttpRequest(client *http.Client, domain string, method string, headers []string) ([]string, error) {
	req, err := http.NewRequest(method, domain, nil)
	var emptyResponse = []string{};

	if err != nil {
		return emptyResponse, err
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
		return emptyResponse, err
	}
	defer resp.Body.Close()

	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return emptyResponse, err
	}
	bodyString := string(bytes)

	if bodyString == "" {
		return emptyResponse, errors.New("DONOTPARSE")
	}

	htmlTokens, err := GetPageStructure(resp.Body)
	if err != nil {
		return emptyResponse, err
	}
	return htmlTokens, nil
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
