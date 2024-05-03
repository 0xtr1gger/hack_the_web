One of the key aspects of reconnaissance is passive subdomain enumeration, a technique that involves gathering information about the target's subdomains without actively interacting with them.

This approach to subdomain enumeration is particularly useful in the early stages of a bug bounty hunt, as it can provide a solid foundation for further investigation and targeted testing.

However, passive enumeration is limited to the information available in public datasets, archives, search engines, certificate transparency logs, and DNS records, which may not be comprehensive or up-to-date. This is why passive subdomain enumeration is conducted essentially in tandem with the active approach.

Techniques for passive subdomain enumeration include, but are not limited to:

- Third-party services
- Public sources
	- Internet archives
	- Developing and collaboration platforms
- Certificate transparency
- Search engine dorks
- Reverse DNS lookup
- Subject alternate name (SAN)
- Favicon hashes
- Reverse `whois`
- DNS Enumeration with Cloudflare
- Rapid7 Project Sonar FDNS enumeration

## Third-party services

Every domain, resource, service, or device alive on the Internet exposes itself in some way. 

For example, to access a resource behind a domain name, one needs to query DNS resolvers for DNS records for that domain to obtain an associated IP address. It is possible to record the results of these DNS queries over time and store them in a dataset. This dataset, in turn, can then be made available for others to query.

The best part of it is that DNS records are not the only information collected and exposed in this way.

Information that can be often found in third-party datasets includes, but is not limited to:

- historical DNS records
- TLS certificates and information available from Certificate Transparency (CT) logs
- resources obtained from crawling and indexing the web
- IP addresses of publicly accessible devices, services, and applications, as well as information about those assets, including ports, protocols, software versions, operating systems, etc.
- information from web archives
- historical WHOIS records

The vast amounts of historical information contained in these databases can be used to determine whether a specific domain was active at some point in time or to retrieve all domains and subdomains associated with a given domain.

The most widely known databases containing information gathered from all reachable corners of the Internet are provided by, for example, [`Shodan`](https://www.shodan.io/) , [`Censys`](https://censys.com/), [`BinaryEdge`](https://www.binaryedge.io/), [`VirusTotal`](https://www.virustotal.com/gui/home/upload), [`SecurityTails`](https://securitytrails.com/), etc. Totally, there are around such [90 services](https://gist.github.com/sidxparab/22c54fd0b64492b6ae3224db8c706228).

Some resources are free; others require API keys. Many API keys are provided for a limited period; some have restrictions on queries per period of time, while others are paid-only. But the results are way more effective with the keys. 

Since it is problematic to query third-party services manually, the process is automated with various tools, including the following.

| tool                                                       | language | tags                                                      | description                                                                                                                                                                   |
| ---------------------------------------------------------- | -------- | --------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Subfinder](https://github.com/projectdiscovery/subfinder) | Go       | #passive_subdomain_enumeration                            | fast passive subdomain enumeration tools that automates querying public and third-party resources for subdomains for a given domain.                                          |
| [Amass](https://github.com/owasp-amass/amass)              | Go       | #subdomain_enumeration<br>#passive_subdomain_enumeration  | the OWASP project that performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques. |
| [Findomain](https://github.com/Findomain/Findomain)        | Rust     | #subdomain_enumeration <br>#passive_subdomain_enumeration | a subdomains monitoring service that provides directory fuzzing, port scanning, vulnerability discovery, and more.                                                            |
| [assetfinder](https://github.com/tomnomnom/assetfinder)    | Go       | #passive_subdomain_enumeration                            | automates querying third-party resources to find domains and subdomains potentially related to a given domain.                                                                |

Other useful resources:
- [`netcraft`](https://searchdns.netcraft.com/)

###### `Amass`

Basic usage:

```bash
amass enum -d domain.com
```

| option   | description                                                        |
| -------- | ------------------------------------------------------------------ |
| `-brute` | perform brute force subdomain enumeration                          |
| `-d`     | domain names separated by commas                                   |
| `-ip`    | show the IP addresses for discovered names                         |
| `-ipv4`  | show the IPv4 addresses for discovered names                       |
| `-ipv6`  | show the IPv6 addresses for discovered names                       |
| `-list`  | print the names of all available data sources                      |
| `-p`     | ports separated by commas                                          |
| `-o`     | path to the text output file                                       |
| `-v`     | output status/debug/troubleshooting info                           |
| `-w`     | path to a different wordlist file for brute forcing                |
| `-trqps` | maximum number of DNS queries per second for each trusted resolver |

One of the notable options is `-p` which allows specifying port numbers to scan. It is often useful to try not only the `433` port (HTTPS), which is set by default, but also `80` (HTTP) and a list of commonly used non-standard ports, such as `8080`, as a subdomain may be hosted on any port.

###### `Subfinder`

[`Subfinder`](https://github.com/projectdiscovery/subfinder) is yet another great tool that queries third-party resources, some of which are not available in Amass. 

Installation:

```bash
# through Go
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# requiers go1.21 or later

# with Git
git clone https://github.com/projectdiscovery/subfinder.git
cd subfinder/v2/cmd/subfinder
go build .
mv subfinder /usr/local/bin/
subfinder -h
```

`subfinder` can be used right after the installation, however many sources required API keys to work. They need to be configured in `Subfinder` configuration file, located at `~/.config/subfinder/provider-config.yaml`

Here is the example of an API configuration file for `Subfinder`:

Sources that require API keys:

```bash
bevigil *
binaryedge *
bufferover *
c99 *
censys *
certspotter *
chaos *
chinaz *
dnsdb *
dnsrepo *
fofa *
fullhunt *
github *
hunter *
intelx *
netlas *
leakix *
passivetotal *
quake *
redhuntlabs *
robtex *
securitytrails *
shodan *
threatbook *
virustotal *
whoisxmlapi *
zoomeyeapi *
facebook *
builtwith *
```

Sources that doesn't require API keys:

```
alienvault
anubis
commoncrawl
crtsh
digitorus
dnsdumpster
hackertarget
rapiddns
riddler
waybackarchive
```

List of all sources supported by `Subfinder`:

| Name             | URL                                                   |
| ---------------- | ----------------------------------------------------- |
| `BeVigil`        | `https://bevigil.com/osint-api`                       |
| `BinaryEdge`     | `https://binaryedge.io`                               |
| `BufferOver`     | `https://tls.bufferover.run`                          |
| `BuiltWith`      | `https://api.builtwith.com/domain-api`                |
| `C99`            | `https://api.c99.nl/`                                 |
| `Censys`         | `https://censys.io`                                   |
| `CertSpotter`    | `https://sslmate.com/certspotter/api/`                |
| `Chaos`          | `https://chaos.projectdiscovery.io`                   |
| `Chinaz`         | `http://my.chinaz.com/ChinazAPI/DataCenter/MyDataApi` |
| `DNSDB`          | `https://api.dnsdb.info`                              |
| `dnsrepo`        | `https://dnsrepo.noc.org`                             |
| `Facebook`       | `https://developers.facebook.com`                     |
| `Fofa`           | `https://fofa.info/static_pages/api_help`             |
| `FullHunt`       | `https://fullhunt.io`                                 |
| `GitHub`         | `https://github.com`                                  |
| `Hunter`         | `https://hunter.qianxin.com/`                         |
| `Intelx`         | `https://intelx.io`                                   |
| `PassiveTotal`   | `http://passivetotal.org`                             |
| `quake`          | `https://quake.360.cn`                                |
| `Robtex`         | `https://www.robtex.com/api/`                         |
| `SecurityTrails` | `http://securitytrails.com`                           |
| `Shodan`         | `https://shodan.io`                                   |
| `ThreatBook`     | `https://x.threatbook.cn/en`                          |
| `VirusTotal`     | `https://www.virustotal.com`                          |
| `WhoisXML` API   | `https://whoisxmlapi.com/`                            |
| `ZoomEye`        | `https://www.zoomeye.org`                             |
| `ZoomEye` API    | `https://api.zoomeye.org`                             |

| option                    | description                                         |
| ------------------------- | --------------------------------------------------- |
| `-d`                      | domains to find subdomains for                      |
| `-dL`                     | file with a list of domains for subdomain discovery |
| `-s`, `-sources`          | use only specific sources for enumeration           |
| `-recursive`              |                                                     |
| `-all`                    |                                                     |
| `-es`, `-exclude-sources` |                                                     |
| `-m`                      |                                                     |
| `-f`                      |                                                     |
| `-rl`, `-rate-limit`      |                                                     |
| `-t`                      |                                                     |
| `-up`                     |                                                     |
| `-o`, `-output`           |                                                     |
| `-oJ`, `-json`            |                                                     |
| `-oD`, `-output-dir`      |                                                     |
| `-cs`, `-collect-sources` |                                                     |
| `-oI`, `-ip`              |                                                     |
| `-config`                 |                                                     |
| `-nW`                     |                                                     |
| `-proxy`                  |                                                     |
| `-ei`, `-exclude-ip`      |                                                     |
| `-v`                      |                                                     |
| `-ls`, `-list-sources`    |                                                     |
| `-silent`                 |                                                     |

To list all available sources:

```bash
subfinder -ls
```

to enumerate subdomains of a single domain:

```bash
subfinder -d target.com
# several targets: subfinder -d target.com,target.net
```

to enumerate subdomains of a list of domains:

```bash
subfinder -dL ./domain_list.txt -v
```

use only specific sources for enumeration:

```bash
subfinder -d target.com -s virustotal,crtsh,github
```

use all sources for enumeration:

```bash
subfinder -d target.com -v -all
```

## Public sources

#### Internet archives

Internet Archives are valuable sources of historical information that can help to discover subdomains of a target domain that have been exposed in the past but hidden to be moment of investigation.

Internet archives:

- [`Internet Archive`](https://archive.org/)
- [`Wayback Machine`](https://web.archive.org/)
- [`Archive.today`](https://archive.ph/)

There are several tools for working with Internet archives. Tools listed below are used to extract all the links related to a particular domain and its subdomains stored in popular archiving platforms. 

| tool                                                        | language | tags                                      | description                                                                                                                                                                                                                  |
| ----------------------------------------------------------- | -------- | ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [waybackurls](https://github.com/tomnomnom/waybackurls)     | Go       | #archive_search                           | Fetches all known URLs from the Wayback Machine archive given a list of domain(s).                                                                                                                                           |
| [waymore](https://github.com/xnl-h4ck3r/waymore)            | Python   | #archive_search                           | The idea behind `waymore` is to find even more links from the Wayback Machine than other existing tools. It fetches URL not only from Wayback Machine, but also from Common Crawl, Alien Vault OTX, URLScan and Virus Total. |
| [gau](https://github.com/lc/gau)                            | Go       | #archive_search <br>#content_discovery    | fetches known URLs from AlienVault's [Open Threat Exchange](https://otx.alienvault.com), the Wayback Machine, Common Crawl, and URLScan for any given domain.                                                                |
| [paramspider](https://github.com/devanshbatham/ParamSpider) | Python   | #archive_search<br>#content_discovery<br> | fetches URLs related to any domain or a list of domains from Wayback archives.                                                                                                                                               |


Then, to extract the subdomains from the obtained results, the [`unfurl`](https://github.com/tomnomnom/unfurl) utility can be used:

```bash
cat urls.txt | unfurl -u [--unique] domains
```

Installation:

```bash
go install github.com/tomnomnom/unfurl@latest

# or
wget https://github.com/tomnomnom/unfurl/releases/download/v0.4.3/unfurl-linux-amd64-0.4.3.tgz
tar xzf unfurl-linux-amd64-0.4.3.tgz
sudo mv unfurl /usr/bin/
```

Below is an example of enumeration using `gau`, the complete process from gathering URLs to combining and sorting subdomains with a list of already existing ones. 

Installation:


```bash
go install github.com/lc/gau/v2/cmd/gau@latest
gau --version

# or
git clone https://github.com/lc/gau.git
cd gau/cmd
go build
sudo mv gau /usr/local/bin/
gau --version
```

The configuration file for `gau` is usually located at `~/.gau.toml` or in the directory where `gau` has been installed, i.e., `~/tools/gau/.gau.toml`.

```bash
gau --subs --o output.txt target.com
cat output.txt | unfurl -u domains > gau_subdomains.txt
sort --output subdomains.txt -u gau_subdomains.txt other_subdomains.txt
```

This method might seem ineffective compared to enumeration with public or third-party resources, but it really yields many <span style="color:#f00000">unique</span> results, even if not as many as with the previous technique.

#### Developing and collaboration platforms

GitHub and GitLab hardly need an introduction. There are numerous tools that can be used to automate scraping and searching information in these platforms, most notably:

| tool                                                              | language | tags           | description                                                                              |
| ----------------------------------------------------------------- | -------- | -------------- | ---------------------------------------------------------------------------------------- |
| [github-subdomains](https://github.com/gwen001/github-subdomains) | Go       | #GitHub_search | Performs searches on GitHub and parses the results to find subdomains of a given domain. |
| [gitlab-subdomains](https://github.com/gwen001/gitlab-subdomains) | Go       | #GitLab_search | Performs searches on GitLab and parses the results to find subdomains of a given domain. |

Installation:

```bash
git clone https://github.com/gwen001/gitlab-subdomains
cd gitlab-subdomains
go install

git clone https://github.com/gwen001/github-subdomains
cd github-subdomains
go install
```

Usage:

>GitHub and GitLab tokens are required. 
```bash
gitlab-subdomains -t <GitLab_token> -o output.txt -d target.com
gitlab-subdomains -t <GitHub_token> -o output.txt -d target.com
```

## Certificate Transparency

>Certificate Transparency (CT) is an Internet security standard and open-source framework for monitoring and auditing digital certificates.

CT creates a system of publicly available certificate transparency logs to record all TLS certificates issued by publicly trusted certificate authorities (CAs), which allows efficient identification of maliciously/mistakenly issued certificates. 

Since CT logs are open and publicly available, they can be used for subdomain enumeration: one can query all the TLS certificates that have been issued for that domain to then reveal the certificates issued to its subdomains.

Logs are available here:
- [`crt.sh`](https://crt.sh/)
- [`Censys`](https://censys.io/)

Also, instead of manually querying domain certificates, one can automate the search with the [`CTRF`](https://github.com/UnaPibaGeek/ctfr) tool written in Python.

| tool                                        | language | tags     | description                                                                                       |
| ------------------------------------------- | -------- | -------- | ------------------------------------------------------------------------------------------------- |
| [CTRF](https://github.com/UnaPibaGeek/ctfr) | Python   | #CT_logs | Queries Certificate Transparency (CT) logs associated with a given domain to find its subdomains. |

Installation:

```bash
git clone https://github.com/UnaPibaGeek/ctfr.git
cd ctfr
pip3 install -r requirements.txt
```

Usage:

```bash
python crtf.py -d github.com -o output.txt
```


Online TLS certificate checkers:
- [`Qualys`](https://www.ssllabs.com/ssltest)
- [`SSLmarket`](https://www.sslmarket.com/ssl-verification-tool/?domain=github.com)
- [`namecheap`](https://decoder.link/sslchecker/)

## Search engine dorks

Even if resources don't appear at the top of search results, it doesn't mean that they haven't been indexed by web crawlers. 

Most of the popular search engines allow the use of specific operators, commonly called search engine dorks, that refine the query to return strictly interesting assets.

Search engine dorks are helpful in discovering hidden and sensitive information related to the target, as well as subdomains of the target domain. The following dork works in most search engines and can be used to retrieve subdomains of a target domain:

```
site:*.target.com 
```

Where `*` asterisk means wildcard.

- [Bing Advanced Search Keywords](https://help.bing.microsoft.com/#apex/bing/en-us/10001/-1)
- [DuckDuckGo Search Syntax](https://help.duckduckgo.com/duckduckgo-help-pages/results/syntax/)
- [Google Advanced Search Operators](https://docs.google.com/document/d/1ydVaJJeL1EYbWtlfj9TPfBTE5IBADkQfZrQaBZxqXGs/edit)

There are tools that can automate subdomain enumeration with search operators:

| tool                                               | language | tags                                               | description                                                                                                                 |
| -------------------------------------------------- | -------- | -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| [GoogleEnum](https://github.com/psjs97/GoogleEnum) | Python   | #Google_dork_automation <br>#subdomain_enumeration | Automates the enumeration of subdomains with Google Dorks.                                                                  |
| [sd-goo](https://github.com/darklotuskdb/sd-goo)   | Bash     | #Google_dork_automation<br>#subdomain_enumeration  | Automates the enumeration of subdomains with Google dorks. It also bypasses page filters and can be used with a VPN or Tor. |

Usage:

```bash
python google_enum.py -d target.com -o ./output.txt
```

Lists of Google Dorks:

- [`7000_google_dork_list.txt`](https://github.com/aleedhillon/7000-Google-Dork-List/blob/master/7000_google_dork_list.txt)
- [`1000 Google Dorks List`](https://gbhackers.com/latest-google-dorks-list/)

## Reverse DNS lookup

In contrast to the resolution of a domain name to an IP address, reverse DNS lookup refers to querying DNS records associated with an IP address in order to identify related domains and subdomains.

The logic behind this is first to discover IP addresses/IP address ranges and then query DNS records associated with these addresses.

IP address ranges can be discovered in multiple ways:

- ASNs discovery 
- query DNS records for already known domains/subdomains (this would be a domain ⇒ IP ⇒ domain mapping). 
- OSINT: `whois` and reverse `whois` 
- identifying CIDR ranges in-scope directly, if given 

Having prepared a list of IP address, one needs to perform a mass DNS querying for these addresses. One of the options is the `HostHunter` tool.


| tool                                                   | language | tags             | description                                                                                                                                                                                          |
| ------------------------------------------------------ | -------- | ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [HostHunter](https://github.com/SpiderLabs/HostHunter) | Python   | #DNS_enumeration | A tool to efficiently discover and extract hostnames provides a large set of target IPv4 or IPv6 addresses. Output can be generated in multiple formats, including CSV, TXT, or Nessus file formats. |

## Subject alternate name (SAN)

A Subject Alternative Name (SAN), aka multi-domain TLS certificate, is an extension to the X.509 specifications that allows multiple subdomains to be protected by a single TLS certificate. [RFC 2818](https://datatracker.ietf.org/doc/html/rfc2818) specifies Subject Alternative Names as the preferred method of adding DNS names to certificates.

SANs can be used to find more subdomains, as well as other domains protected by the same certificate. 

Domain names protected by a single SAN certificate can be extracted manually with OpenSSL:

```bash
openssl s_client -connect domain.com:443 2>/dev/null | openssl x509 -noout -ext subjectAltName | grep -oP '(?<=DNS:|IP Address:)[^,]+'|sort -uV
```

Decryption:

- `openssl s_client -connect domain.com:443`
	- retrieves the digital certificate of `domain.com` by connecting to it over HTTP (port `443`).
- `2>/dev/null`
	- throws away error messages.
- `openssl x509 -noout -ext subjectAltName`
	- prints only the SAN record.
- `grep -oP '(?<=DNS:|IP Address:)[^,]+'|sort -uV`
	- arranges subdomains into a nice column.

Example:

```bash
openssl s_client -connect wikimedia.org:443 2>/dev/null | openssl x509 -noout -ext subjectAltName | grep -oP '(?<=DNS:|IP Address:)[^,]+'|sort -uV
```
```
mediawiki.org
w.wiki
wikibooks.org
wikidata.org
wikifunctions.org
wikimedia.org
wikimediafoundation.org
wikinews.org
wikipedia.org
wikiquote.org
wikisource.org
wikiversity.org
wikivoyage.org
wiktionary.org
wmfusercontent.org
*.mediawiki.org
*.m.mediawiki.org
*.m.wikibooks.org
*.m.wikidata.org
*.m.wikimedia.org
*.m.wikinews.org
*.m.wikipedia.org
*.m.wikiquote.org
*.m.wikisource.org
*.m.wikiversity.org
*.m.wikivoyage.org
*.m.wiktionary.org
*.planet.wikimedia.org
*.wikibooks.org
*.wikidata.org
*.wikifunctions.org
*.wikimediafoundation.org
*.wikimedia.org
*.wikinews.org
*.wikipedia.org
*.wikiquote.org
*.wikisource.org
*.wikiversity.org
*.wikivoyage.org
...
```
The process can also be automated with the [`san_subdomain_enum`](https://github.com/appsecco/the-art-of-subdomain-enumeration/blob/master/san_subdomain_enum.py) Python script:

```bash
python ./san_subdomain_enum.py domain.com
```

| tool                                                                                                                 | language | tags                       | description                                                                                                            |
| -------------------------------------------------------------------------------------------------------------------- | -------- | -------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| [san_subdomain_enum](https://github.com/appsecco/the-art-of-subdomain-enumeration/blob/master/san_subdomain_enum.py) | Python   | #SAN_subdomain_enumeration | Extracts domains and subdomains listed in Subject Alternate Name (SAN) records of TLS certificates for a given domain. |





