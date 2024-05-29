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

## Web spidering 

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

## Directory brute-force

>Web directory and file brute-force enumeration involves systematically trying to access directories and files in a web application by guessing their names with a wordlist.

Directory brute-forcing aims to enumerate hidden files and directories inside a web application by systematically probing for known or common paths with a dictionary. The principle is straightforward: possible paths are substituted as a request parameter through a wordlist. It can be either directory names or common full paths to files. 

```
https://target.com/admin
https://target.com/admin.php
https://target.com/Admin
. . .
https://target.com/robots.txt
https://target.com/.well-known/security.txt
https://target.com/dev/
. . . 
```

>N.B.: Brute-force enumeration implies sending numerous requests to the server; it should be carried out with caution to avoid accidental DoS attacks ~~and not end up on trial~~.
>The preferable approach is to impose a delay between requests or limit the number of requests per second. In this case, enumeration will take longer, but this is considered polite and safe testing.

>N.B.: The enumeration is better conducted on top of directories previously discovered with a web spider to deepen the discovery and increase the chances of finding sensitive locations.

Directory brute-force can be automated with various tools:

| tool                                                 | language | tags                                                           | description                                                                                                                                                                                                                                                          |
| ---------------------------------------------------- | -------- | -------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [ffuf](https://github.com/ffuf/ffuf)                 | Go       | #fuzzing                                                       | A fast and flexible web fuzzer written in Go.                                                                                                                                                                                                                        |
| [wfuzz](https://github.com/xmendez/wfuzz)            | Python   | #fuzzing                                                       | A simple web fuzzer that replaces any reference to the `FUZZ` keyword by the value in a wordlist.                                                                                                                                                                    |
| [dirsearch](https://github.com/maurosoria/dirsearch) | Python   | #directory_bruteforce                                          | a fast and flexible directory enumeration tool. supports filtering, usage of proxy servers, wordlist formats, and many other features.                                                                                                                               |
| [gobuster](https://github.com/OJ/gobuster)           | Go       | #bruteforce<br>#directory_bruteforce <br>#subdomain_bruteforce | Gobuster is a tool used to brute-force:<br><br>- URIs (directories and files) in web sites.<br>- DNS subdomains (with wildcard support).<br>- Virtual Host names on target web servers.<br>- Open Amazon S3 buckets<br>- Open Google Cloud buckets<br>- TFTP servers |
| [dirstalk](https://github.com/stefanoj3/dirstalk)    | Go       | #directory_bruteforce                                          | a modern alternative to `dirb`. a multi threaded application designed to bruteforce paths on web servers.                                                                                                                                                            |

But honestly, it doesn't really matter which enumeration tool is used because they all work on the same principle. Choosing the right tool is entirely up to personal preference.

Rather, the key to successful enumeration is the choice of the right wordlists to be used, and how they will be used.


#### Efficiency: on wordlists


Many bug hunters make the same mistake: they use the same wordlist for enumeration of the contents of each target application in every part of it.

But you can't really hope to find .NET files, such as `.aspx`, on a Linux server running a PHP website. Similarly, searching for `.jsp` files under the domain dedicated to static assets such as images and CSS, e.g., `assets.target.com`, makes very little sense either. Otherwise this is just a waste of time, bandwidth, and electrical power.

Instead, wordlists should be tailored to the technologies used in the web application and on the target web server.

>This doesn't mean that you can't use general wordlists at all. To get a general overview of the application, a quick run through a small list of the most common paths might be a good idea. However, more thorough investigations should be more focused.

In general, when choosing a wordlist for directory and file enumeration, consider the following two factors:

- the underlying technology stack of the application
- the purpose of the part of the tested application

The technologies used in the application can be determined using fingerprinting techniques. Here is a whole article dedicated for this: [[🖉fingerprinting]].

One of the most promising strategies to identify the technology stack powering the application is to analyze already-discovered files. Pay attention to configuration files, file extensions, and directory names: all of these may indicate the programming languages and frameworks used in the application.

Once you have an idea of what's behind the application, pick an appropriate wordlist and then start enumeration. Below are several notable options:

| resource                                                                   | description                                                                                                                                                                                           |
| -------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [awesome-wordlists]()                                                      | A curated list of wordlists for bruteforcing and fuzzing.                                                                                                                                             |
| [Assetnote Wordlists](https://wordlists.assetnote.io/)                     | One of the largest sets of wordlists for enumeration of different kinds: API endpoints, subdomains, directories and files, files specified to technologies, e.g., for Flask, Laravel, Nginx, etc.     |
| [SecLists](https://github.com/danielmiessler/SecLists)                     | A collection of multiple types of lists for fuzzing, enumeration, and vulnerability testing.                                                                                                          |
| [trickest wordlists](https://github.com/trickest/wordlists)                | Regularly updated information security wordlists.                                                                                                                                                     |
| [xajkep wordlists](https://github.com/xajkep/wordlists?tab=readme-ov-file) | A quite old, but still useful collection of wordlists of various kinds, including language dictionaries (English, French, Spanish, Irish, etc.), file discovery (PHP, ASP, JSP, etc.), and much more. |
| [Bug-Bounty-Wordlists](https://github.com/Karanxa/Bug-Bounty-Wordlists)    | A repository with a wide variety of wordlists for testing and enumeration, including server-specific (Nginx, Tomcat, etc.) and technology-specific (SQL, WordPress, ASP, etc.) lists for enumeration. |
| [KaliLists](https://github.com/3ndG4me/KaliLists/tree/master)              | Default lists from Kali Linux, useful when Kali itself is not in use.                                                                                                                                 |
| [random-robbie](https://github.com/random-robbie/bruteforce-lists)         | a good collection of wordlists for enumeration sorted by  technology.                                                                                                                                 |

#### On responses: status codes

Whether a certain requested page does or doesn't exist is usually determined based on response codes returned by the server.

The server's response codes are commonly used to determine whether a requested page exists or not.

Generally, `4xx` codes indicate that the requested resource doesn't exist, while `2xx` are signs of successful discovery. However, this rule is not universally applied: many applications handle requests for nonexistent resources by returning custom error messages, or `200` response codes. Furthermore, some requests for existing resources may result in a non-`200` response. 

For this reason, it is recommended to not fall into conclusions hastily. Instead, first walk through the application to watch how the server handles requests to existing and non-existent resources, malformed requests, requests to protected resources, and so on. On the whole, responses tend to be consistent throughout the application (but not always), and based on the gathered data, it is much easier to analyze results from brute-force enumeration.

## Strategy

To summarize all the strategies discussed, below is a rough sketch of a methodology that can be used to enumerate files and directories of a web application:

1. Run a web spider to get a general idea of the application. 

2. Analyze the results. Walk through the list of obtained URLs:
	
	- Are there file extensions or directory/file names that indicate the programming language and frameworks in use?

	- Seek to fingerprint the underlying technology stack. This will significantly reduce the number of files and directories to probe.

	- Try to understand how the server deals with requests for different resources. Make several manual requests for known valid and invalid resources, paying attention to:
		- redirects
		- status codes
		- request parameters

	- Identify the file/directory naming conventions used by developers; note frequently encountered words and collocations specific to the application. 

3. Pick several wordlists relevant to the technology stack of the application from open-source collections. Additionally, based on your notes, generate custom wordlists for enumeration; this can be automated with tools like [`CeWL`](https://github.com/digininja/CeWL), [`crunch`](https://salsa.debian.org/debian/crunch), [`bopscrk`](https://github.com/r3nt0n/bopscrk), etc. 

3. Use brute-force enumeration tools to send requests to the target server and iterate over the prepared list.

4. Analyze the responses received from the server. Based on the information gathered previously, try to identify valid resources.
