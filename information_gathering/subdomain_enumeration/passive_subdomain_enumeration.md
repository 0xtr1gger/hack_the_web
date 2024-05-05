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

`Amass` is a Swiss army knife for subdomains enumeration, an OWASP project, that outperforms passive enumeration the best.

Installation:

```bash
go install -v github.com/owasp-amass/amass/v4/v4.2.0
```

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

One of the notable options is `-p` which allows you to specify port numbers to scan. It is often useful to try not only the `433` port (HTTPS), which is set by default, but also `80` (HTTP) and a list of commonly used non-standard ports, such as `8080`, as a subdomain may be hosted there either.

More information on how to use the tool can be found in the [`Amass user guide`](https://github.com/owasp-amass/amass/blob/master/doc/user_guide.md).

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

Sources that doesn't require API keys:

```
alienvault
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

Here is a little cheatsheet (it is not comprehensive, but only includes (subjectively) the most commonly used options).

| option                    | description                                                                           |
| ------------------------- | ------------------------------------------------------------------------------------- |
| `-d`                      | domains to find subdomains for                                                        |
| `-dL`                     | file with a list of domains for subdomain discovery                                   |
| `-s`, `-sources`          | use only specific sources for enumeration                                             |
| `-recursive`              | use only sources that can handle subdomains recursively                               |
| `-all`                    | use all sources for enumeration (slow)                                                |
| `-es`, `-exclude-sources` | sources to exclude from enumeration                                                   |
| `-m`, `-match`            | subdomain or list of subdomain to match (file or comma separated)                     |
| `-f`, `-filter`           | subdomain or list of subdomain to filter (file or comma separated)                    |
| `-rl`, `-rate-limit`      | maximum number of http requests to send per second                                    |
| `-t`                      | number of concurrent goroutines for resolving (only with `-active`), default is `10`  |
| `-up`, `-update`          | update subfinder to latest version                                                    |
| `-o`, `-output`           | output file                                                                           |
| `-oJ`, `-json`            | write output in JSON                                                                  |
| `-oD`, `-output-dir`      | directory to write output (`-dL` only)                                                |
| `-cs`, `-collect-sources` | include all sources in the output                                                     |
| `-oI`, `-ip`              | include host IP in output (`-active` only)                                            |
| `-pc`, `-provider-config` | provider config file, default `/home/username/.config/subfinder/provider-config.yaml` |
| `-nW`, `-active`          | display active subdomains only                                                        |
| `-proxy`                  | http proxy to use with subfinder                                                      |
| `-ei`, `-exclude-ip`      | exclude IPs from the list of domains<br>                                              |
| `-v`                      | show verbose output<br>                                                               |
| `-ls`, `-list-sources`    | list all available sources                                                            |
| `-silent`                 | show only subdomains in output                                                        |

To list all available sources:

```bash
subfinder -ls
```

to enumerate subdomains of a single domain and save the results into a file:

```bash
subfinder -d target.com -o subdomains.txt
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

Besides, instead of manually querying domain certificates, one can automate the search with the [`CTFR`](https://github.com/UnaPibaGeek/ctfr) tool, written in Python.

| tool                                        | language | tags     | description                                                                                       |
| ------------------------------------------- | -------- | -------- | ------------------------------------------------------------------------------------------------- |
| [CTFR](https://github.com/UnaPibaGeek/ctfr) | Python   | #CT_logs | Queries Certificate Transparency (CT) logs associated with a given domain to find its subdomains. |

Installation:

```bash
git clone https://github.com/UnaPibaGeek/ctfr.git
cd ctfr
pip3 install -r requirements.txt
```

For convenience (this makes `ctfr` available globally in the system, not only in the `ctfr` directory, and allows to invoke it with under the alias `ct`):

```bash
mv ./ctfr.py /usr/local/bin
chmod u+x /usr/local/bin
alias ct='ctfr.py'
```

Usage:

```bash
ct -d github.com -o ct.txt
```
![ctfr-github com](https://github.com/0xtr1gger/hack_the_web/assets/167773454/4c67c3c5-167d-486b-bee7-4e39219ccc92)

The problem with `ctfr` is that it also outputs wildcards, as there might be certificates that are created for multiple domains. To remove lines with `*.` characters, the `grep` command can be used. But prior to it, save wildcards, also with `grep`, for future investigation just in case (these subdomains are very likely to be valid, and are likely to contain interesting subdomains deeper).

```bash
# to save all wildcards in a seprate file:
cat ct_subdomains.txt | grep "*." > ct_wildcards.txt

# to remove wildcards:
cat ct_subdomains.txt | grep -v [--invert-match] "*." > ct_subdomains.txt
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

>All the methods are described [here](https://github.com/0xtr1gger/hack_the_web/blob/main/information_gathering/subdomain_enumeration/IP_address_range_discovery.md).

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

![SAN-subdomain-wikimedia](https://github.com/0xtr1gger/hack_the_web/assets/167773454/32e5cc3e-af67-4a4a-9299-d6550edbd531)


The process can also be automated with the [`san_subdomain_enum`](https://github.com/appsecco/the-art-of-subdomain-enumeration/blob/master/san_subdomain_enum.py) Python script:

```bash
python ./san_subdomain_enum.py domain.com
```

| tool                                                                                                                 | language | tags                       | description                                                                                                            |
| -------------------------------------------------------------------------------------------------------------------- | -------- | -------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| [san_subdomain_enum](https://github.com/appsecco/the-art-of-subdomain-enumeration/blob/master/san_subdomain_enum.py) | Python   | #SAN_subdomain_enumeration | Extracts domains and subdomains listed in Subject Alternate Name (SAN) records of TLS certificates for a given domain. |

## Favicon hashes

>A <span style="color:#f00000">favicon</span> (favorite icon), aka website icon, tab icon, URL icon, etc., is a file containing one or more small icons associated with a particular website or web page. It is displayed to the left side of the webpage title the tabs, bookmarks, and links bars.

![favicon_wiki](https://github.com/0xtr1gger/hack_the_web/assets/167773454/0ee9c5d9-d7a2-42db-9f3a-68cfbf6a605d)

Typically, favicons are in ICO, SVG, and PNG formats, but they can also be JPEG or even animated GIF pictures. 

Favicons are interesting as that they can help to find domains and subdomains related to the target website, as website owners tend to use the save favicon image across all or most of their resources. 

For search, a hash function is applied to the icon to obtain its hash-string representation, which will serve as an identifier for the favicon. The most common hash function used for that purpose is called <span style="color:#f00000">MurmurHash</span>. 

The obtained hash value can then be used to search with various search engines, such as `Shodan`, which calculates MurmurHash values for every single favicon it discovers and indexes this information

```
https://www.shodan.io/search?query=http.favicon.hash:FAVICON_HASH
```

Most often, favicons are located at `https://domain.com/favicon.ico` addresses under the target domain. However, just as there are various image formats that can be used for favicons, there are a vast variety of places where the favicon can reside. 

A better way to find a favicon is to inspect the HTML source code of the page with a favicon, then search for keywords such as `favicon`, `fav`, `.ico`, `.img`, `.svg`, etc. It may be needed to manually examine the code to find the link to the image. Favicons are commonly specified in the `<head>` section of an HTML document, usually right after `<title>`, in the `<link>` tag with the attribute `rel="icon"`:


```HTML
<head>  
  <title>page with a favicon</title>  
  <link rel="icon" type="image/x-icon" href="/images/favicon.ico">  
</head>  
<body>
```

Apart from target subdomains, favicon hashes are useful in identifying fishing websites. For this reason, unfortunately, results obtained from a favicon hash search can be full of false positives (this depends on the target itself).

Here is a tiny Python script to retrieve a MurmurHash from a favicon:

```Python
import mmh3
import requests
import codecs

response = requests.get('https://domain.com/favicon.ico')
favicon = codecs.encode(response.content, 'base64')
mmhash = mmh3.hash(favicon)
print(mmhash)
```

To install MurmurHash Python library, `mmh3`:

```bash
pip install mmh3
```

![mmh_python](https://github.com/0xtr1gger/hack_the_web/assets/167773454/feefb913-194e-45db-80ab-d936e20a5af5)


Online services to retrieve favicon hashes:
- [`favicon-hash`](https://favicon-hash.kmsec.uk/)

Resources to search by favicon hashes:
- [Shodan](https://shodan.io)
- [CriminalIP](https://www.criminalip.io/)

[OWASP](https://owasp.org/www-community/favicons_database) also hosts a small community-driven database of MD5 favicon hashes consisting of about 5.7 hundred entries.

The last, but not least to mention, is [`FavFreak`](https://github.com/devanshbatham/FavFreak) tool written in Python that can be used to automate the whole process of calculating and searching by favicon hashes.

## Reverse `whois`

WHOIS is a protocol for querying databases dedicated to storing information about domain name registrants and registries. WHOIS databases include domain names, IP address blocks, ASNs, and contact information for a given registrant or registry. It is widely used in bug hunting and penetration testing during the reconnaissance stage.

In turn, reverse WHOIS is a method of searching for domain names based on the registrant's WHOIS database information. E.g., suppose a domain name `target.com` is registered by John Doe, who has an email address `johndoe@email.com`. The logic behind reverse WHOIS is to search for any other domains that list the same email address, `johndoe@email.com`, in the registrant's contact field. If `subdomain.target.com` or `domain.com` have the same registrant, they are probably related.

Reverse WHOIS is more helpful in open-scope programs, but subdomains can also be discovered in this way.

>The reverse `whois` lookup refers to querying the WHOIS database by name, address, phone number, email, and other information about the registrant organization to retrieve all the domain names related to that organization. With this technique, it might be possible to identify assets of the target company that are not tied to it in any other way.

There are many online resources that offer reverse WHOIS search:

- [`BigDomainData`](https://www.bigdomaindata.com/reverse-whois/)
- [`reversewhois.io`](https://www.reversewhois.io/)
- [`Viewdns.info`](https://viewdns.info/reversewhois/)
- [`osint.sh`](https://osint.sh/reversewhois/?__cf_chl_f_tk=SdZ4wNfJiVLHWUv56QZ2BmhxGn9BM95BOxmeYtCdNNA-1714630838-0.0.1.1-1493)
- [`domainq`](https://www.domainiq.com/reverse_whois)
- [`WhoisFreaks`](https://whoisfreaks.com/tools/whois/reverse/search)
- [`WHOXY`](https://www.whoxy.com/reverse-whois/)

## DNS Enumeration with Cloudflare

After registering for a free account at [Cloudflare](https://www.cloudflare.com), one can add any domain to their list. This can be done by logging into the Cloudflare dashboard and clicking on the "Add site" option. Then, Cloudflare itself will enumerate subdomains of a given domain based on data available to it, and return it in JSON format with `A`, `AAAA`, and `CNAME` records for each subdomain. And among all goods, the scanning is quite fast, usually no more than a couple of minutes.
## Rapid7 Project Sonar FDNS enumeration

[Rapid7 Project Sonar](https://opendata.rapid7.com/) actively scans the Internet to gather data about millions of domain names, and subsequently provides access to the datasets for query, either for free or, at times, for a fee.

One of the key datasets hosted by Project Sonar is a collection of the `ANY` DNS queries for millions of domains. The dataset is useful for identifying DNS misconfigurations and gaining insights into the attack surface, aside from disclosing subdomains.

>`ANY` DNS query, aka wildcard DNS queries, are a type of DNS query that returns all records of all types known to the name server for a given domain name. 

In other words, when an `ANY` query is sent to a DNS server, the server returns all records of all types (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `PTR`, `SRV`, `SOA`, `TXT`, `CAA`, `DS`, and `DNSKEY`) for the specified domain name. 

Querying Rapid7 datasets requires an account and is deeply time-consuming. However, it often returns a huge number of subdomains that nobody would ever be able to find using vanilla approaches.


