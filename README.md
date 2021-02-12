# fuzzparam

## What is?

A fast go based duplicate domains remover

TL;DR
> Give it list of URL's and it will find the sites that have similar source code and remove them


## Download

Download and Build it using following command:
```
$ git clone https://github.com/0xsapra/dedupe
$ cd dedupe
$ go build dedupe.go  
```


## Flags supported

| Flag      | Description | Example |
| ----------- | ----------- | ----------- |
| -x   | Proxy Url        | -x http://127.0.0.1:8080 |
| -c   | Concurrency/threads(Default 25)        | -c 100 |


## Usage

```bash
$ echo "https://site.com\nhttps://site2.com\nhttps://site.com/asdf.php\n" | ./dedupe  
```

OR
```bash
$ echo "https://site.com\nhttps://site2.com\nhttps://site.com/asdf.php\n" > domains.txt

$ cat domains.txt | ./dedupe
```

OR, 
use it will other tools. Like projectdiscovery's `httpx`. [https://github.com/projectdiscovery/httpx](https://github.com/projectdiscovery/httpx)
and, tomnonnom's `waybackurls` [https://github.com/tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls)

```bash
$ cat domains.txt | waybackurls | httpx | ./dedupe 
```
