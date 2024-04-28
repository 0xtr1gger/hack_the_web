Active subdomain enumeration goes beyond passive techniques like searching through public databases or archives. It involves actively probing the target domain's infrastructure to identify live subdomains that may not be readily visible. This proactive approach allows to uncover overlooked or forgotten subdomains that could pose security risks.

Techniques for active subdomain enumeration include, but are not limited to:
- Brute-force enumeration, aka dictionary attack
- Virtual host enumeration
- `Content-Security-Policy` HTTP header
- Content discovery

## Brute-force enumeration

Brute-force subdomain enumeration aims to uncover new assets simply by systematically guessing subdomains with substitutions through a wordlist and then connecting to target servers to check whether a given subdomain is alive or not.

In other words, a long list of common subdomain names is prepended to a target domain, one name at a time, and then an attempt to resolve the obtained FQDN is performed.

- `www`              ⇒ `www.target.com`
- `api`              ⇒ `api.target.com`
- `assets.api` ⇒ `assets.api.target.com`

Obviously, not all combinations will be valid, and thus the resulting list of active subdomains will be much smaller than the initial one.

This method is useful to reveal subdomains that are neither indexed by search engines or third-party services nor connected to existing subdomains with TLS certificates or DNS records. Sometimes, subdomains may be abandoned and forgotten even by their owners, and brute-forcing is one of the few, if not the only, ways to discover these assets.

Brute-forcing can be conducted using either specialized tools or plain fuzzers, such as the famous `ffuf`.

Subdomain brute-force enumeration tools:

| tool                                            | language | tags                                                                      | description                                                                                                                          |
| ----------------------------------------------- | -------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| [puredns](https://github.com/d3mondev/puredns)  | Go       | #subdomain_enumeration <br>#domain_resolver<br>#subdomain_brute-force<br> | A fast domain resolver and subdomain brute-forcing tool that can accurately filter out wildcard subdomains and DNS poisoned entries. |
| [SubBrute](https://github.com/TheRook/subbrute) | Python   | #subdomain_enumeration <br>#subdomain_brute-force                         | A fast subdomain enumeration tool.                                                                                                   |


Fuzzing tools:

| tool                                      | language | tags     | description                                                                                       |
| ----------------------------------------- | -------- | -------- | ------------------------------------------------------------------------------------------------- |
| [ffuf](https://github.com/ffuf/ffuf)      | Go       | #fuzzing | A fast and flexible web fuzzer written in Go.                                                     |
| [wfuzz](https://github.com/xmendez/wfuzz) | Python   | #fuzzing | A simple web fuzzer that replaces any reference to the `FUZZ` keyword by the value in a wordlist. |

Wordlists to use:

| wordlist                                                                                                  | description                                                                                                                                                                                                                                                                                                                                                                                                                 | tags                   |
| --------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------- |
| [2m-subdomains.txt](https://wordlists-cdn.assetnote.io/data/manual/2m-subdomains.txt)                     | 2 million+ subdomains from [Assetnote](https://wordlists.assetnote.io/), generated from the GitHub dataset on BigQuery.                                                                                                                                                                                                                                                                                                     | #subdomain_brute-force |
| [best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)             | 9 million+ subdomains from Assetnote. Manually generated, one of the most comprehensive.                                                                                                                                                                                                                                                                                                                                    | #subdomain_brute-force |
| [n0kovo_subdomains](https://github.com/n0kovo/n0kovo_subdomains/blob/main/n0kovo_subdomains_huge.txt)     | 3 million+ subdomains have been created by [N0kovo](https://github.com/n0kovo) by scanning the whole IPv4 and collecting all the subdomain names from the TLS certificates. Check out [this blog](https://n0kovo.github.io/posts/subdomain-enumeration-creating-a-highly-efficient-wordlist-by-scanning-the-entire-internet/#benchmarking-) to see how effective this brute-force wordlist compared to other big wordlists. | #subdomain_brute-force |
| [six2dez_small_wordlist](https://gist.githubusercontent.com/six2dez/a307a04a222fab5a57466c51e1569acf/raw) | 102k subdomains created by [six2dez](https://github.com/six2dez) suitable for running from a personal computer.                                                                                                                                                                                                                                                                                                             | #subdomain_brute-force |

Wordlist collections:

| wordlist                                                                | description                                                                                                                                                                         | tags                                                         |
| ----------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| [Assetnote](https://wordlists.assetnote.io/)                            | One of the best collections of wordlists for various purposes.                                                                                                                      | #subdomain_brute-force <br>#directory_bruteforce<br>#fuzzing |
| [awesome-wordlists]()                                                   | A curated list of wordlists for brute-forcing and fuzzing.                                                                                                                          | #subdomain_brute-force <br>#directory_bruteforce<br>#fuzzing |
| [SecLists](https://github.com/danielmiessler/SecLists)                  | A collection of multiple types of wordlists for fuzzing, enumeration, and vulnerability testing.                                                                                    | #subdomain_brute-force <br>#directory_bruteforce<br>#fuzzing |
| [Bug-Bounty-Wordlists](https://github.com/Karanxa/Bug-Bounty-Wordlists) | A repository with a wide variety of wordlists for testing and enumeration, including server- (Nginx, Tomcat, etc.) and technology-targeted (SQL, WordPress, ASP, etc.) enumeration. | #subdomain_brute-force <br>#directory_bruteforce<br>#fuzzing |
| [wordlists](https://github.com/xajkep/wordlists?tab=readme-ov-file)     | A collection of wordlists of various kinds, including language dictionaries (English, French, Spanish, Irish, etc.), file discovery (PHP, ASP, JSP, etc.), and much more.           | #subdomain_brute-force <br>#directory_bruteforce<br>#fuzzing |

## Virtual Hosts enumeration

><span style="color:#f00000">Virtual hosting</span> is a method for hosting multiple domain names on a single server. This allows one server to share its resources, such as memory and processor cycles, without requiring all services provided to use the same host name.

In other words, a single web server can host multiple websites under multiple domain names or subdomains. Each virtual host, in turn, is identified by its hostname and represents a domain or subdomain. 

Virtual host enumeration refers to the process of identifying virtual hosts associated with a single IP address. 

In particular, this refers to the enumeration of virtual hosts implemented with<span style="color:#f00000"> name-based virtual hosting</span>. In contrast to IP-based virtual hosting, where each hosted web application is associated with a unique IP address, name-based virtual hosting allows multiple websites to be hosted under a single IP address but with different hostnames. Name-based virtual hosting also contributes to conserving IPv4 addresses, since to host multiple websites, one needs to allocate only one address. And this is why it is more common.

There are two ways to access different virtual hosts under the same IP address, depending on the protocol in use:


- HTTP
	- The hostname of the target virtual host is specified in the `Host` HTTP header. The web server parses the header and redirects the request to the appropriate backend. 

- HTTPS
	
	- The <span style="color:#f00000">Server Name Indication</span> (<span style="color:#f00000">SNI</span>) extension of TLS is used for accessing virtual hosts with HTTPS. When SNI is used, the client specifies the target hostname prior to the TLS handshake. 

	- At this point, the SNI extension is the only practical way to support access to virtual hosts using HTTPS. The reason is that the server needs to provide the digital certificate for the requested hostname.
	- However, the server is not aware of which certificate to present during the handshake, since the TLS handshake takes place before the expected hostname and other headers are sent to the server. This is also the reason the `Host` header is meaningless when using HTTPS.


To learn more about HTTPS virtual hosting: [`SNI: Virtual Hosting for HTTPS`](https://www.ssl.com/article/sni-virtual-hosting-for-https/).

- To enumerate virtual hosts accessed through HTTP, it is enough to fuzz the `Host` HTTP header values:

```bash
ffuf -u http://target.com -w ~/wordlists/subdomains.txt -H "Host: FUZZ.target.com"
```

- The same can also be achieved using the Nmap [`http-vhosts`](https://nmap.org/nsedoc/scripts/http-vhosts.html) NSE script:

```bash
nmap --script http-vhosts -p 80,8080,443 <target>
```

- If no meaningful hostname is specified either in the `Host` HTTP header or prior to the TLS handshake in the frames of the SNI extensions, the server redirects requests to the default virtual host. To access the default virtual host, specify a gibberish value in the `Host` HTTP header, leave it empty, or specify the target IP address in place of the hostname:

```bash
curl  -H "Host: junk" http://target.com
```

For enumeration of virtual hosts accessed through HTTPS, alteration of the header won't work due to the nature of how HTTPS connections are established. 

One way to enumerate virtual hosts accessed with the SNI extension is to query for all TLS certificates associated with a given IP address, and then discover the domain names to which these certificates have been assigned. This can be done either manually with `openssl` tool, or automatically with tools.


```bash
openssl s_client -connect [IP_address]:443 -showcerts
```

This will display all the certificates presented by the server, including any additional certificates used for virtual hosts. In this case, it might also be fruitful to probe different port numbers, at least the most popular ones. Look for the `Subject:` and `Issuer:` fields in the output to identify the domains and subdomains associated with the certificates.


- The `nmap` tool in tandem with the [`ssl-cert`](https://nmap.org/nsedoc/scripts/ssl-cert.html) NSE script can be used to automate the process of querying certificates for a range of IP addresses or port numbers:

```bash
nmap -p 443 -sV -v --script ssl-cert [IP_address_range]
# the -v option is needed to display the Subject: and Issuer: fields in the output. 
```

- Tools like `sslscan` can be used to perform more comprehensive TLS analysis, including enumeration of virtual hosts based on TLS certificates:

```bash
sslscan [IP_address]
```

- The `amass` tool can be used to automate the query for TLS certificates 

```bash
amass intel -active <IP address>
# or, for multiple IP addresses
amass intel -active -cidr <IP address range>/<CIDR network mask>
```

There are also multiple online tools that can help to retrieve TLS certificates:
- [`DigiCert SSL Certificate Checker`](https://www.digicert.com/help/)
- [`DNSCHECKER SSL Checker`](https://dnschecker.org/ssl-certificate-examination.php)
- [`MXTOOLBOX HTTPS Lookup & SSL Check`](https://mxtoolbox.com/HTTPSLookup.aspx)

It also might be possible to determine to what domain a given certificate belongs by decoding and analyzing gathered certificates. One of the ways is to use online tools:

- [`keycdn tools Certificate Decoder`](https://tools.keycdn.com/ssl)

Copy the obtained certificates and paste it to a certificate decoder. 

## `Content-Security-Policy`

The HTTP `Content-Security-Policy` response header is used to implement Content Security Policy (CSP), which helps to detect and mitigate several types of attacks, including Cross-Site Scripting (XSS) and other injections. 

In particular, the `Content-Security-Policy` header is used to specify the domain names of the resources that are allowed to be loaded from a given page.

For example, to ensure that all the content from the online banking application residing on a separate subdomain is loaded using TLS from the current page on whatever domain, an administrator of a web application might specify the following:

``` 
Content-Security-Policy: default-src https://banking.domain.com 
```

This header, _in_ _addition_ _to_ defending users of an application from eavesdropping by enforcing TLS, also discloses the subdomain `banking.target.com`. Hence, it is possible to discover new subdomains by querying the CSP header.

To query response headers, the `curl` tool with the `-I` header will be used. Then, `grep` is used to filter the `Content-Security-Policy` header:

```bash
curl -I -L target.com | grep -i [--ignore-case] -E [--extended-regexp] "Content-Security-Policy|CSP"
```





