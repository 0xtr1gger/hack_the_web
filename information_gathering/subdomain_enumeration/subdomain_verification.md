Passive subdomain enumeration techniques, such as querying public databases or using search engines, may provide obsolete and irrelevant results, as passive sources rely on historical data. A massive list of gathered subdomains can be full of false positives. 

To cope with it, all passively gathered subdomains need to be verified. 

There are three methods for subdomain verification:
- Using public DNS resolvers (passive)
- Interrogating target servers directly (active)
- Conducting visual reconnaissance (active)

>There is always an opposite situation: the obtained list of subdomains, even if all of them are verified, is never guaranteed to be exhaustive. And the only way to deal with it is to combine multiple subdomain enumeration technique and monitor for new subdomains.

## Public DNS resolvers

A DNS resolver is responsible for initiating and sequencing the queries that eventually lead to the complete resolution of a domain name to an IP address. Every time a domain needs to be checked to make sure it is valid, a DNS resolver must be involved.

>N.B.: any DNS resolver queries for domains on behalf of its client. This means that a public resolver won't help to hide the identity of the client.

The mechanism is straightforward: a list of subdomains, one subdomain at a time, is supplied to a public DNS resolver. If the FQDN is valid, the resolver will return an IP address; it will return nothing otherwise.

One of the most widely used tools for automating massive DNS resolution is `MassDNS`. [`MassDNS`](https://github.com/blechschmidt/massdns) is a simple and high-performance tool designed to automate massive domain name resolution (on the order of millions or even billions of entries). Without special configuration, `MassDNS` can handle over 350,000 names per second using public DNS resolvers.

| tool                                               | language  | tags                  | description                                                                                       |
| -------------------------------------------------- | --------- | --------------------- | ------------------------------------------------------------------------------------------------- |
| [MassDNS](https://github.com/blechschmidt/massdns) | C, Python | #subdomain_resolution | A high-performance tool for massive domain name resolution automation using public DNS resolvers. |

`MassDNS` needs to be provided with a list of resolvers themselves. 

An extensive list of public DNS resolvers can be found here: 
- https://public-dns.info/
This website includes around 62.7k name servers from 193 countries around the world.

Unfortunately, not all resolvers will work at any given moment. For this reason, resolvers need to be validated before submitting them to `MassDNS`.

~~Validating DNS resolvers to validate subdomains.~~

The [`dnsvalidator`](https://github.com/vortexau/dnsvalidator) tool automates the verification of IPv4 (and only IPv4) DNS servers for their relevance. A trial domain name is queried against several trusted servers, such as Google `8.8.8.8`, Cloudflare `1.1.1.1` and Quad9 `9.9.9.9`. Then, the tested resolver is queried for the same domain. And if it returns a response that differs from the baseline, it gets skipped immediately. The process is repeated for all resolvers in the list.

Indeed, `dnsvalidator` is a resource- and time-consuming tool, as it sends out numerous DNS queries to each tested resolver. As a result, security researchers have created and are maintaining resources containing lists of valid DNS resolvers, updated every 24 hours. One of them is [`Trickest`](https://trickest.com/), whose list of public resolvers is available at the following address:

```
https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt
```

Besides, there is an entire [repository](https://github.com/trickest/resolvers) created by enthusiasts that presents sources to search for lists of reliable DNS resolvers.

In the end, for everyday use, there is no need to verify DNS resolvers by yourself, although it is important to know about that. 

If one chooses to validate DNS resolvers on their own way, this should not be done from a regular desktop on a home network. A VPS (Virtual Private Server) is recommended to be used to perform any bandwidth-intensive and resource-consuming tasks, such as running `dnsvalidator`. Home routers are not designed to handle that much bandwidth.

To summarize:

1. Prepare a list of subdomains to be verified.

2. Find a frequently updated and publicly available list of active DNS resolvers, such as  [`Trickest list of resolvers`](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt).
	- Alternatively, acquire a list of public DNS resolvers from a website such as https://public-dns.info/ and run `dnsvalidator` to verify whether they are relevant or not.

3. Supply a list of validated public DNS resolvers and the list of domains that should be checked to `MassDNS`.

## Interrogating target servers

This method repeats one of the active subdomain enumeration techniques, not to discover new subdomains, but to verify already obtained ones.

A list of probable subdomains is supplied to a tool like [`puredns`](https://github.com/d3mondev/puredns) or [`SubBrute`](https://github.com/TheRook/subbrute), or to a web fuzzer such as [`ffuf`](https://github.com/ffuf/ffuf) or [`wfuzz`](https://github.com/xmendez/wfuzz) for versification (the same tools as used for active subdomain enumeration). 

Obviously, this attracts as much attention as subdomain brute force does. Therefore, in the end, using public DNS resolvers is a preferred approach, although this method is viable too.
