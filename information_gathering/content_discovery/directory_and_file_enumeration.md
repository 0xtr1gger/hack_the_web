Content:

1. Directory and file enumeration
2. Web spidering
	1. `hakrawler`
	2. `Photon`
	3. `katana`
3. Directory brute-force
	1. Efficiency: on wordlists


The key idea behind directory and file enumeration is to discover hidden or unreferenced pages on web applications that may expose sensitive information or functionality. 

Directory and file enumeration aims to reveal the structure of the application and index pages within the website in a structured manner: everything from evident places visible for everyone, to hidden content and functionality not intended to be public, but still accessible for those who manage to find it.

Recon is useless if the information gathered cannot be used to plan attacks. The objectives of directory and file enumeration can be thought of as follows:

- enumerate functionality on the website
- fingerprint technologies used to build be website
- identify the attack vectors

This article aims to describe methods primarily on how to construct a blueprint of the target application and index starting points for further investigation. Namely:

- web spidering
- directory bruteforcing

Both methods are considered active as they require direct interaction with the application, but serve different purposes.

- Web spidering is effective in enumerating visible content on the website, or pages referenced from other pages in the application. However, this method is not helpful in locating hidden webpages, in contrast to brute-force enumeration.

- Dictionary brute-force has proven to be effective in detecting locations detached from the main application: it complements the results of web spiders with previously undiscovered files and directories.

- ## Web spidering 

>Web spidering, aka web crawling, involves recursive scanning of web pages for links pointing to other pages under the same domain, then following every found link and repeating the process until no links are left. 

The process is automated with programs called (surprisingly) web crawlers, or spiders.

The crawler starts with a list of seed URLs, which serve as initial entry points. It works by parsing each page for links to other pages, indexing the URLs found, and adding them to a queue of pages to visit. The crawler proceeds by following each link in the queue, adding new URLs for future exploration. This process continues recursively until no links to be visited can be found.

It is important to understand the limitations of this approach: web spidering is useful only for the enumeration of directories and files that are referenced elsewhere in the application. Such pages are typically expected to be visible by design, although they can still happen to contain sensitive data.

Nevertheless, this step is essential to constructing an initial blueprint of the application and understanding its purpose and functionality. The results obtained from web spiders are useful as starting locations for dictionary brute-forcing and other methods of content investigation.

There are many open-source web crawlers available, including:

| tool                                                     | language | tags                      | description                                                                                                                                                                                                    |
| -------------------------------------------------------- | -------- | ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [harkawler](https://github.com/hakluke/hakrawler)        | Go       | #spidering                | Fast Golang web crawler for gathering URLs and JavaScript file locations.                                                                                                                                      |
| [Photon](https://github.com/s0md3v/Photon)               | Python   | #spidering<br>#OSINT<br>  | A fast web spider that extracts URLs (in-scope and out-of-scope), URL parameters, files, secret keys, strings matching custom regex, subdomains, etc. from the visible web content.                            |
| [katana](https://github.com/projectdiscovery/katana)     | Go       | #spidering                | Fast and configurable web crawler with automatic form filling, scope control, and customizable output.                                                                                                         |
| [crawlergo](https://github.com/Qianlitp/crawlergo)       | Go       | #spidering                | A fast web crawler that intelligently fills forms and automatically submits them, collects URLs, JavaScript, page comments, and `robots.txt` files, and automatically fuzzes common paths.                     |
| [crawley](https://github.com/s0rg/crawley)               | Go       | #spidering                | Crawls web pages and prints any link it can find.                                                                                                                                                              |
| [dirhunt](https://github.com/Nekmo/dirhunt)              | Python   | #spidering                | A web crawler that optimizes searching for directories and their analysis. It detects false 404 errors and searches directories in `robots.txt`, VirtusTotal, Google, Common Crawl, and `archive.org`.         |
| [LinkFinder](https://github.com/GerbenJavado/LinkFinder) | Python   | #spidering<br>#JS_parsing | A Python script written to discover endpoints and their parameters in JavaScript files.                                                                                                                        |
| [SecretFinder](https://github.com/m4ll0k/SecretFinder)   | Python   | #spidering<br>#JS_parsing | A Python script based on [LinkFinder](https://github.com/GerbenJavado/LinkFinder), written to discover sensitive data like API keys, access tokens, authorization credentials, JWTs, etc. in JavaScript files. |
| [gospider](https://github.com/jaeles-project/gospider)   | Go       | #spidering                | Fast web spider written in Go.                                                                                                                                                                                 |
| [SpiderSuite](https://github.com/3nock/SpiderSuite)      | C++      | #spidering<br>#GUI        | Multi-feature GUI web crawler written in C++.                                                                                                                                                                  |

Web crawling can also be conducted manually, with a web proxy and tons of patience. This is useful, for example, in situations where an automatic tool can't handle atypical or complex navigation mechanisms through the application. But, in most cases, automated tools cope with the task perfectly fine.

>[`Gin&Juice`](https://ginandjuice.shop/) is a website created by PortSwigger for testing automatic web tools like crawlers or fuzzers. In this article, it is used for demonstration to avoid interrogation of real applications.

#### `hakrawler`

`hakrawler` is a fast and simple web spider. It supports custom HTTP headers, proxies, output in JSON, and several other features.

Installation:

```bash
# Kali Linux
sudo apt install hakrawler

# with Git
git clone https://github.com/hakluke/hakrawler
cd ./hakrawler
go build .
mv ./hakrawler /usr/local/bin

# with Go
go install github.com/hakluke/hakrawler@latest
```

Options:

| option      | description                                                                                              |
| ----------- | -------------------------------------------------------------------------------------------------------- |
| `-d`        | Depth to crawl, 2 by default.                                                                            |
| `-dr`       | Disable following HTTP redirects.                                                                        |
| `-h`        | Custom headers separated by two semi-colons, e.g. `-h "Cookie: name=value;;Referer: http://domain.com/"` |
| `-i`        | Only crawl inside path.                                                                                  |
| `-insecure` | Disable TLS verification.                                                                                |
| `-json`     | Output as JSON.                                                                                          |
| `-proxy`    | Proxy URL, e.g. `-proxy http://127.0.0.1:8080`<br>                                                       |
| `-s`        | Show the source of URL based on where it was found, e.g., `href`, form, script, etc.                     |
| `-size`     | Page size limit, in KB.                                                                                  |
| `-subs`     | Include subdomains for crawling.                                                                         |
| `-t`        | Number of threads to utilize, 8 by default.                                                              |
| `-timeout`  | Maximum time to crawl each URL from `stdin`, in seconds.                                                 |
| `-u`        | Show only unique URLs.                                                                                   |
| `-w`        | Show at which link the URL is found.                                                                     |


Basic usage:

```bash
echo https://ginandjuice.shop/ | hakrawler
```

```
https://ginandjuice.shop/
https://ginandjuice.shop/catalog
https://ginandjuice.shop/blog
https://ginandjuice.shop/about
https://ginandjuice.shop/my-account
...
```

Only show unique URLs:

```bash
echo https://ginandjuice.shop/ | hakrawler -u
```

Include subdomains:

```bash
echo https://ginandjuice.shop/ | hakrawler -subs
```

Only crawl inside a specific path:

```bash
echo https://ginandjuice.shop/ | hakrawler -i
```

```
https://ginandjuice.shop/blog
https://ginandjuice.shop/blog/post?postId=3
https://ginandjuice.shop/blog/post?postId=4
https://ginandjuice.shop/blog/post?postId=4
https://ginandjuice.shop/blog/post?postId=6
https://ginandjuice.shop/blog/post?postId=6
https://ginandjuice.shop/blog/post?postId=2
. . .
```

Show the source of the URL based on where it was found:

```bash
echo https://ginandjuice.shop/ | hakrawler -u -s
```
```
[href] https://ginandjuice.shop/
[href] https://ginandjuice.shop/catalog
[href] https://ginandjuice.shop/blog
. . .
[script] https://ginandjuice.shop/resources/js/react.development.js
[script] https://ginandjuice.shop/resources/js/react-dom.development.js
. . .
[form] https://ginandjuice.shop/login
. . .
```

Show at which link which URL has been found:

```bash
echo https://ginandjuice.shop/ | hakrawler -u -w
```

```
[https://ginandjuice.shop/blog] https://ginandjuice.shop/
[https://ginandjuice.shop/blog] https://ginandjuice.shop/catalog
[https://ginandjuice.shop/blog] https://ginandjuice.shop/blog
[https://ginandjuice.shop/blog] https://ginandjuice.shop/about
[https://ginandjuice.shop/blog] https://ginandjuice.shop/my-account
[https://ginandjuice.shop/blog] https://ginandjuice.shop/catalog/cart
. . . 
```

Crawl multiple URLs:

```bash
cat urls.txt | hakrawler
```

![hakrawler_gin juice](https://github.com/0xtr1gger/hack_the_web/assets/167773454/41064abe-dd64-4b1a-aea2-013dfc76a46e)


#### `Photon`

`Photon` is a fast web crawler with a wealth of options.

During scanning, it retrieves the following information:
- URLs (in-scope and out-of-scope)
- URLs + query string parameters
- emails, links to social media accounts, Amazon buckets and other information (external links)
- files, including JavaScript files
- secret keys (e.g., authentication and API keys)
- API endpoints
- strings matching custom regex
- subdomains $ DNS-related data

The extracted information is saved in an organized manner or can be exported as JSON.

Installation:

```bash
git clone clone https://github.com/s0md3v/Photon
cd Photon
pip install -r requirements.txt
```

Usage:

```bash
python3 ./photon.py -u https://ginandjuice.shop --level 2 --verbose 
```

`Photon` organizes all discovered assets in files by category and prints out a summary of the investigation. It also crawls for external URLs and stores them separately.

![Photon_gin juice shop](https://github.com/0xtr1gger/hack_the_web/assets/167773454/e53af937-6fdf-47ad-9cbd-1adde82551e3)

#### `katana`

`katana` is a highly customizable tool for web crawling with a myriad of options. 

Installation:

```bash
git clone https://github.com/projectdiscovery/katana
cd ./katana/cmd/katana
go build .
```

```bash
katana -u https://ginandjuice.shop
```

![katana_hin juice shop](https://github.com/0xtr1gger/hack_the_web/assets/167773454/447355c7-ab93-439f-86bf-9d74efd7659c)



