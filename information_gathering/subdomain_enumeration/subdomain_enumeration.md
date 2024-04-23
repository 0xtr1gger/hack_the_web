>Subdomain enumeration is the process of discovering and indexing subdomains for a given domain.

Subdomain enumeration helps to expand the attack surface, with each subdomain representing a potential attack vector.

Each subdomain represents a potential attack vector. Separate applications, development and testing environments, administrative interfaces, or infrastructure components may be hosted under different subdomains, each of which being an opportunity to discover vulnerabilities.

Subdomain enumeration helps to expand the attack surface and find hidden, forgotten, insecure functionality and sensitive information.

Subdomain enumeration techniques can be divided into two types:

- Passive subdomain enumeration
    - Enumeration is conducted without direct interaction with the target; all subdomain information is gathered from publicly available sources or with the help of third-party services.

- Active enumeration
    - Involves direct interaction with target web servers.

In <span style="color:#f00000">passive</span> subdomain enumeration, an attacker gathers information about subdomains by appealing to public or third-party resources without directly connecting to the target servers or any parts of the infrastructure; while <span style="color:#f00000">active</span> approach involves explicit interaction.
## Passive subdomain enumeration

Passive enumeration draws significantly less attention than an active approach, excludes any chances for triggering protection mechanisms such as rate limiting, and therefore can be considered as a preferred method for investigation.

However, passive enumeration may not always be as steadily unmistakable as active, since the information available in public for each organization varies somewhat significantly. In addition, the results tend to be full of false positives due to outdated information. For this reason, all the results gathered with any of the passive techniques should be verified either actively or passively.

In the end, the proper use of passive enumeration in tandem with careful verification regularly yields strong results.

The cornerstone of subdomain enumeration is to be versatile in the choice of reconnaissance techniques, be they passive or active. The more techniques are used, the more chances there are to find interesting subdomains that others might have overlooked.

>All the techniques mentioned are described in this article: [link].

Passive subdomain enumeration methods include:

- Third-party services
	- Querying third-party datasets of historical DNS query results, provided by services like [`SecurityTrails`](https://securitytrails.com/), [`Censys`](https://censys.io/), [`Shodan`](https://www.shodan.io/), [`BinaryEdge`](https://www.binaryedge.io/), [`VirusTotal`](https://www.virustotal.com/gui/), [`WhoisXMLAPI`](https://main.whoisxmlapi.com/), etc. The use of these services doesn't involve sending any requests directly to the target server, but rather querying independent databases.

- Certificate Transparency
	- Analyzing TLS certificates issued for a given domain to find certificates associated with its subdomains by inspecting publicly available append-only Certificate Transparency (CT) logs.

- Search engine dorks
	- Using search engine advanced search operators to find indexed resourced hosted under subdomains of a given domain.

- Reverse DNS lookup
	- Reverse DNS lookup refers to querying for DNS records associated with an IP address to find related domain names, rather than resolving a domain to an IP address. A reverse lookup is applied to a prepared list of IP addresses that belong to the target. These IP addresses can be collected in various ways, but the most notable are:
	    - identifying ASNs (Autonomous System Numbers) and IP address ranges allocated for it
	    - inspecting DNS records associated with already found subdomains

- Subject alternative name (SAN)
	- Retrieving multi-domain TLS certificates, aka SAN (Subject Alternate Name) records. This method exploits the fact that organizations tend to use a single TLS certificate to protect a domain and its subdomains all at once, rather than issuing certificates for each domain name separately. 

- Favicon hashes
	- A creative way to enumerate subdomains by searching for pages that use the same favicon as used in the main application. For search, favicons are identified with hashes.

- Reverse `whois`
	- Involves querying for whois records to find domains and subdomains associated with the same particular entity based on contact information left by that entity. Typically, this follows a regular whois lookup against the target domain that aims to find information about the entity in the first place.

- DNS Enumeration with Cloudflare
	- Cloudflare owns a CDN (Content Delivery Network), a network of caching servers distributed across the world, used for delivering content into different corners of Earth without compromising performance while waiting for the response from the distant server initially responsible for the content. Cloudflare offers a feature to query the Cloudflare-hosted DNS records for the target domains to find their subdomains.

Techniques for enumeration are, without any doubt, valuable. However, as mentioned, it is crucial to verify the results returned from public or third-party resources. There are three main ways to do that:

- Interrogate target servers directly
	- Send a number of requests to subdomains and analyze the status codes from the HTTP responses. This is considered as an active reconnaissance technique, and for large targets, may require sending hundreds of queries.

- Use public DNS resolvers
	- The preferred approach is to use publicly available DNS resolvers. A DNS resolver is responsible for initiating and sequencing the queries that eventually lead to the complete resolution of a domain name to an IP address. If a resolution is successful and the returned IP address is valid, the subdomain exists. Public resolvers are mass-queried through the list of collected subdomains to find the ones that are currently alive.

- Conduct visual reconnaissance 
	- There are numerous tools that automatically take screenshots of pages from a prepared list. This is sometimes called visual reconnaissance. One of the most notable such tools is the `Eyewitness`. Taking screenshots of pages hosted under gathered subdomains accomplishes two tasks at once: detecting irrelevant domains by searching for `404` response codes and gaining insights about functionality and content hosted on live subdomains. Since to take screenshots, utilities send requests to the target servers directly, it is also considered an active technique.

## Active subdomain enumeration

Active subdomain enumeration involves direct interaction with target servers to identify subdomains of a given domain.

Active subdomain enumeration techniques include:

- Brute-force enumeration, aka dictionary attack
	- Guessing subdomains by enumerating through a wordlist. The approach assumes sending numerous requests to the servers and entails the risk of being blocked or rate-limited; however, it is effective in finding subdomains that have never been exposed publicly.

- Virtual host enumeration
	- Refers to the process of identifying various web applications hosted under a single IP address but different subdomains, aka name-based virtual hosts. Depending on the protocol used to access these virtual hosts (HTTP or HTTPS), this either involves fuzzing the values of the `Host` HTTP header or querying TLS certificates associated with the given IP address.

- Zone transfers
	- Zone transfers are becoming increasingly uncommon in real-world scenarios, yet they remain a viable means of identifying target subdomains. Zone files are gathered by querying for `AXFR` DNS records associated with a domain.

- `Content-Security-Policy` HTTP header
	- The HTTP `Content-Security-Policy` response header allows website administrators to manage the resources the browser is allowed to load for/from a given page. By examining the value of this header on different pages hosted by a given domain, it may be possible to find out its subdomains.

## Permutations & recursive enumeration

On the base of the set of already gathered and verified subdomains, it is possible to discover even more with two methods:

- Permutations
	- Generating and querying permutations/combinations/alterations of already known subdomains, in conjunction with a few of the most common words used in subdomains, e.g., `ftp`, `dev`, `www`, etc.

- Recursive enumeration
	- Enumerating subdomains of subdomains. 

- - - 
TBD: roadmap of subdomain enumeration
