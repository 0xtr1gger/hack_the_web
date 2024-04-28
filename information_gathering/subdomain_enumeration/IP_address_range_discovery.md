Information gathering is the cornerstone of a successful vulnerability assessment. Before any security audit, it is essential to identify the Internet-facing resources owned or associated with the target: this helps to expand the attack surface and increase the chances of finding vulnerabilities. The process involves identifying IP addresses, domains, and subdomains, as any of these assets could potentially be vulnerable to exploitation. This article explores the discovery of IP address ranges.

N.B.: Prior to IP address and DNS investigation, it is helpful to conduct open-source intelligence and get an overview of the target.

One of the main reasons for collecting information about the target IP address space is that the collected IP addresses can help with subdomain enumeration:

- In-scope subdomains can be hosted at completely different IP addresses and serve distinct applications; each of them could have vulnerabilities.

- A single domain or subdomain may resolve to multiple IP addresses, where each IP address points to a server that hosts a copy of a target web application. 
	- This is done to distribute the load among several machines. Requests from clients are evenly distributed among all the available servers by load balancers. Nonetheless, it is not guaranteed that the servers are identical: the absence of a particular vulnerability in one back-end server does not guarantee that another server is not vulnerable either, as there is always a possibility of misconfigurations and inconsistencies among the servers.

There are several common ways to investigate the target IP address space:
- ASNs
- DNS records
- `whois` and reverse `whois`

## ASNs

One of the most effective methods for identifying the target IP address range is by finding the ASN that belongs to the assessed organization.

>An autonomous system (AS) is a collection of one or more IP prefixes managed by a single administrative entity or domain, such as a university, government, commercial organization, or internet service provider (ISP).

>An autonomous system number (ASN) is a unique identification number assigned to an autonomous system (AS) by the Internet Assigned Numbers Authority (IANA). 

Every AS controls a specific set of IP addresses, called an IP address block.

ASNs, along with IP addresses, are managed by RIRs (Regional Internet Registries). RIRs are assigned to blocks of AS numbers from IANA (Internet Assigned Numbers Authority). And then the appropriate RIRs assign groups of ASNs to LIRs (Local Internet Registries), most of which are ISPs, enterprises, or academic institutions.

There are two types of AS numbers:
- 16 bit (2 bytes) ASNs (`0` - `65,535`)
- 32 bit (4 bytes) ASNs (`0` - `4,294,967,295`)
The numbers are written in the form `AS <number>`.

Obviously, not all entities are assigned to their own ASNs, but this is the case with large organizations. If an attacker is lucky (or prescient) to target such an organization, they might discover more assets of the target by looking for an ASN assigned to the organization and inspecting an IP address range controlled by the AS.

An AS is defined by the IP address range it is assigned to it. Hence, to find an ANS, it is needed to look for an ASN with an IP address block to which a known target IP address (e.g., the IP address to which an in-scope domain resolves) belongs to.

Information about the IP address ranges and the corresponding ASNs is available on the RIRs websites, which are responsible for registering these ASNs. There are 5 RIRs in the world:

| Acronym  | Name                                                         | Rgions                                                            | Website                                    |
| -------- | ------------------------------------------------------------ | ----------------------------------------------------------------- | ------------------------------------------ |
| AFRINIC  | the African Network Information Center                       | Africa                                                            | [www.afrinic.net](https://www.afrinic.net) |
| ARIN     | the American Registry for Internet Numbers                   | Antarctica, Canada, parts of the Caribbean, and the United States | [www.arin.net](https://www.arin.net/)      |
| APNIC    | the Asia Pacific Network Information Center                  | East Asia, Oceania, South Asia, Southeast Asia                    | [www.apnic.net](https://www.apnic.net)     |
| LACNIC   | the Latin America and Caribbean Network Information          | Latin America and most of the Caribbean                           | [www.lacnic.net](https://www.lacnic.net/)  |
| RIPE NCC | Le Réseaux IP Européens Network Coordination Centre (French) | Europe, Central Asia, Russia, West Asia                           | [www.ripe.net](https://www.ripe.net/)      |

In turn, what IP addresses belong to what RIRs can be found at the [IANA website](https://www.iana.org/assignments/as-numbers/as-numbers.xhtml).

However, in rare situations, an organization may have several ASNs, and this approach will not discover any other AS but the one to which the requested address belongs. For such cases, there are various online services that can help obtain ASNs for a company name or domain name, but the results are not always reliable.

More or less comprehensive and accurate information can be found at `HURRICATE ELECTRIC`:
- [`HURRICATE ELECTRIC`](https://bgp.he.net/)
	- provides a search by a company name to find all relevant AS numbers, as well as information about each AS number: the country of registration, the website of the organization that has been assigned to this AS number, and statistics about AS numbers.


ASNs can also be found with `amass`:

- by a domain name:

```bash
amass intel -d domain.com -whois
```

- by a company name:

```bash
amass intel -org 'organization name'
```

Once the ASN is discovered, `Amass` can be used in an attempt to resolve the corresponding IP addresses to domain names:

```bash
amass intel -asn xxxxx
```

There are also various resources that can help find an organization that is assigned to a given AS number (ASN ⇒ organization, not vice versa):

- [`ASNLOOKUP`](https://asnlookup.com/)
	- looks for information about specific ASNs, organizations, CIDRs, or registered IP addresses.
- [`DNSCHECKER`](https://dnschecker.org/asn-whois-lookup.php)
	- provides `whois` data for an ASN, as well as the company responsible for the given ASN, the country or city of the origin of the company, etc.
- [`ASRank`](https://asrank.caida.org/asns/6427)
	- helps to discover information for a particular ASN, as well as AS relationships and rank.

There is an [`asn`](https://github.com/nitefood/asn/) tool available on GitHub, created by [`nitefood`](https://github.com/nitefood), which can be used to find ASNs by an IP address. By the way, the output is very colorful and cute.

```
asn -u 192.168.0.1
```

Obviously, the search for AS numbers can be quite cumbersome. Not all resources provide comprehensive or even relevant results, but the method is still worth it. More methods to discover ASNs can be found here:

- [`SecurityTrails: ASN Lookup Tools, Strategies and Techniques`](https://securitytrails.com/blog/asn-lookup#autonomous-system-lookup-script)

## DNS records

TBD <3

## `whois` and reverse `whois`

TBD <3


