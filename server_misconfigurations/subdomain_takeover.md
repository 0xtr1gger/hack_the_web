>A <span style="color:#f00000">subdomain takeover</span> vulnerability occurs when an attacker exploits a DNS record that redirects a subdomain to an inactive or non-existent external resource, and takes control over that subdomain. This can lead to phishing, malware distribution, defacement, or other malicious activities.

There are several possible reasons of subdomain takeover vulnerabilities:
- a `CNAME` DNS record points to a third-party domain name available for registration by an attacker;
- a `A` or `AAAA` DNS record indicate an IP address not controlled by the target and is available for registration by an attacker;
- a `NS` record contains a domain name that points to a non-existing name server and is available for registration.

According to [OWASP](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover), this vulnerability can be exploited with a wide variety of DNS resource records, such as `MX` and `TXT`, apart from the mentioned ones. Indeed, any vacant domain name or IP address is a chance to occupy it yourself. However, `CNAME`, `A`, `AAAA`, and (rarely) `NS` subdomain takeovers are more likely to occur in the wild and have much more severe consequences compared to `MX` or `TXT` takeovers.

## Subdomain takeover: `CNAME` records

#### `CNAME` records and subdomain takeover

Subdomain takeover vulnerability caused by misconfigured `CNAME` records arises when the subdomain has a canonical name (`CNAME`) pointing to a *third-party resource*, but no host is providing content for it. One possible reason for this, for example, is that the virtual host has not yet been published or has been deleted by now.

>The `CNAME` (Canonical Name) DNS records are used to create an alias from one domain name to another domain name, called canonical name.

```
alias.target.com.        CNAME   canonical.name.com.
```

Each time a DNS server queries a domain name with a `CNAME` record, this triggers another DNS lookup for the domain name indicated in that record. This can be thought of as a redirection.

When a subdomain with a `CNAME` record is not used, an attacker can take over that subdomain by registering it by themselves and providing their own virtual host for it. 

![subdomain_takeover](https://github.com/0xtr1gger/hack_the_web/assets/167773454/4c3744f4-819b-4273-8e3b-b482f3070ee0)

Suppose a subdomain of a tested application, `subdomain.target.com`, has a `CNAME` record pointing to another domain hosted on a third-party service, such as GitHub pages: `username.github.io`. If no content is provided for `username.github.io`, an attacker might be able to register a GitHub page under the same domain name by themselves. Then, for example, each time a user requests `subdomain.target.com`, they will be redirected to `username.github.io`, controlled by an attacker.

>If a certain subdomain with a `CNAME` record pointing to a third-party provider, such as GitHub, AWS S3, Google Cloud, etc., is accessible, but returns a `404 Not Found` or similar error page, this indicates that the subdomain might be vulnerable to subdomain takeovers. 

And that's all.

A good illustration of how subdomain takeovers work can be found in this write-up:
- [Simple Subdomain Takeover](https://infosecwriteups.com/simple-subdomain-takeover-15129e19bbb4)

#### Example: GitHub pages

1. Suppose a user, John, creates a GitHub page to host the content of his blog, under the domain `johndoe.github.io`.

2. John decides to move his blog to his personal website, `target.com`, and use a [custom domain](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/about-custom-domains-and-github-pages) for it. 

3. John registers a subdomain, `blog.target.com`, and creates a `CNAME` record that points to the previous location of the application at `johndoe.github.io`. This allows him to not migrate all the files of the blog web application to his own servers and configure everything from scratch, but just to set an alias to the old location of the blog.

```
blog.target.com.        CNAME   johndoe.github.io.
```

>N.B.: In the `CNAME` record, the left-hand label is an alias for the right-hand side, which is a canonical name ([RFC 2181](https://datatracker.ietf.org/doc/html/rfc2181#section-10.1.1)).

4. Now, everyone who navigates to `blog.target.com`, invokes a DNS query to resolve the domain to an IP address. The `CNAME` record of the domain triggers another DNS lookup, this time for the canonical name, `johndoe.github.io`. Thereby, the user is redirected to `johndoe.github.io`. This DNS delegation using a `CNAME` record is entirely transparent to the user, i.e., it happens in the background during DNS resolution.

5. After some time, John again decides to migrate their blog to another domain and host application files on proprietary servers. The virtual host that had been providing content for the old GitHub page, `johndoe.github.io`, is now removed and is free for anyone to register. In the background, the subdomain `blog.target.com` has not been deleted for some reason, and the `CNAME` record still points to the `johndoe.github.io.`. This means that anyone who navigates to `blog.target.com` will see an `404 Not Found` error message from GitHub pages.

6. One day, an attacker probes subdomains of John's website. They notices that the `blog.target.com` has a `CNAME` record pointing to `johndoe.github.io`, However, the `blog.target.com` itself returns a `404 Not Found` page, as, indeed, no content is provided for it. Finally, the attacker notices they can register the `johndoe.github.io` by themselves and take control over it, therefore they does that. Now, every time a user navigates to `blog.target.com`, they, similarly, ends up at `johndoe.gitub.io`, but this time controlled by the attacker. This is the subdomain takeover.

## `A` and `AAAA` subdomain takeover

Another common cause of the vulnerability is a misconfigured `A` or `AAAA` DNS record.

>`A` records, aka address records, are used to resolve a domain name to an IPv4 address, which is 32 bits long. `AAAA` records, aka Quad `A` records, in turn, are used to resolve a domain name to an IPv6 address, which is 128 bits long.

If a domain name has a `A` or `AAAA` DNS record that points to an IP address that is no longer controlled by the original owner and is available for registration, the subdomain takeover vulnerability occurs. 

```
NAME                  TYPE
----------------------------------------------------------
blog.target.com       A       192.106.0.10
blog.target.com       AAAA    2706:4700:90::fbec:5bed:a9a9
```

In this case, an attacker can lease the IP address indicated in a `A` or `AAAA` record of the vulnerable domain name, then host their application on that address. Each time a user visits the compromised subdomain, a DNS resolver returns an IPv4 address that points to a virtual host controlled by an attacker.

## `NS`-based subdomain takeover

Subdomain takeover is also possible with `NS` records. It is sometimes called *DNS takeover*.
#### `NS` records

>An `NS` record, or nameserver record, is a type of DNS record user to specify the authoritative name server(s) for a domain.

Authoritative name servers are the DNS servers that contain the up-to-date DNS records for a specific domain, say `target.com`, including `A` and `AAAA` records that hold the IP address to which the domain resolves. The `NS` record tells recursive DNS resolvers which name servers are authoritative for a particular zone or domain, i.e., to which servers to query to resolve the domain name to an IP address. 

It is not stated that the server pointed to in the record is the only one who carries the valid record for the domain, as the authoritative name server only holds a copy of the zone. However, there are no guarantees to find the necessary A/AAAA records for the domain on any other arbitrary name server, either.

Therefore, if there were no records for a domain, the DNS resolver simply wouldn't know where to find DNS records for that domain, i.e., which server to query. There would be no way to resolve the domain to an IP address.

Let me show a practical example:

```bash
dig ns github.com @1.1.1.1
```

![dig_ns_github_1 1 1 1](https://github.com/0xtr1gger/hack_the_web/assets/167773454/8b03b869-753a-4e68-abb2-dcb982d1854f)


For `github.com`, for example, there are eight authoritative name servers that guarantee to have `A` or `AAAA` records for that domain. This means that if a DNS resolver queries any of these servers, it will assuredly get an IP address for the domain.

>**`MX` subdomain takeover** 
>`MX` subdomain takeover is analogous to other types of vulnerability, but is much rarer. `MX` records are used to specify the mail server responsible for accepting email messages on behalf of a domain name to which the record is assigned. The vulnerability can allow an attacker to intercept and read emails; nevertheless, the impact of an `MX` subdomain takeover is relatively low compared to other types of subdomain takeovers, such as `NS` or `CNAME` takeovers.
#### Non-existing nameservers 

What if a domain indicated in the `NS` record points to a non-existing nameserver?
And what if that domain is available for registration? Exactly. Subdomain takeover vulnerability arises. 

Needless to say, nameserver domains, such as `ns-520.awsdns-01.net.`, won't usually be available for registration. However, this might be the case with any other subdomains, as the DNS specification neither requires nameservers to be on the same domain nor have any specific naming pattern. So, if a domain happens to have an `NS` record that points to any domain available for registration, this is indeed a subdomain takeover vulnerability.

>If the domain name of at least one name server pointed to in the `NS` record is available for registration, it is vulnerable to the `NS` subdomain takeover.

The question is: does this ever happen? The answer is yes, although this form of subdomain takeover is quite uncommon. Read the following article to see the reality of this approach with the real case from Matthew Bryant: 

- [`The International Incident – Gaining Control of a .int Domain Name With DNS Trickery - Matthew Bryant, The Hacker Blog`](https://thehackerblog.com/the-international-incident-gaining-control-of-a-int-domain-name-with-dns-trickery/index.html)

## Identification and testing

The general principle of searching and testing for subdomain takeover can be as follows.

1. Subdomain enumeration
	
	- Enumerate as many subdomains of a target domain as possible, with both passive and active reconnaissance techniques. 
	- Subdomain enumeration is extensively described in [these articles](https://github.com/0xtr1gger/hack_the_web/tree/main/information_gathering/subdomain_enumeration).

2. Gather DNS records for each of the subdomains
	
	- Use `dnsrecon`, `dig`, or other tools to collect and analyze DNS records associated with the enumerated subdomains.

3. Identify which DNS records are dead and point to inactive/not used services. 
	
	- Query and inspect `A`, `AAAA`, `CNAME`, and `NS` DNS records for each of the enumerated subdomains in an attempt to find dangling DNS records.
	
4. Try to access resources indicated in the DNS records, i.e., IP addresses or domain names. 

	- If any of the requested resources return error pages, such as `404 Not Found`, or don't respond at all, it is a good reason to conduct further investigation.

Perform a basic DNS enumeration on the target domain using `dnsrecon`:

```bash
dnsrecon -d target.com
```

Identify which DNS resource records are dead and point to inactive/not-used services with the `dig` command. For example, for `CNAME` records:

```bash
dig CNAME target.com
```

The following response messages from `dig` warrant further investigation:

- `NXDOMAIN`
	- `NXDOMAIN` is a response from a DNS server that indicates that the domain name referenced in the DNS query doesn't exist. This can occur when the requested domain name is *not registered*.
	- However, `NXDOMAIN` doesn't guarantee that the domain can be registered by the attacker either. A subdomain can't be taken over if, for example, this subdomain is under a restricted top-level domain (e.g., `.gov`, `.mil`) or is reserved.

- `SERVFAIL
	- `SERVFAIL` indicates that the DNS server encountered an error when processing the request.

- `REFUSED`
	- The `REFUSED` response indicates that the name server is refusing to perform operations for policy reasons, such as blocking a particular device or prohibiting a certain operation, such as zone transfer. But this answer may also signify a misconfiguration, which leaves a subdomain vulnerable to takeover.

- `no servers could be resolved`
	- This message is sometimes returned when the `dig` command is unable to resolve any DNS servers for the subdomain. 

For example:

![NXDOMAIN](https://github.com/0xtr1gger/hack_the_web/assets/167773454/6b9906b0-6c92-4ebf-9b69-89bc4db32f3a)

- Read more about various DNS responses here:
	- https://bluecatnetworks.com/blog/the-top-four-dns-response-codes-and-what-they-mean/
	- https://blog.cloudflare.com/unwrap-the-servfail


Testing can also be automated with tools; however, it is a bad idea to fully rely on automation (until it is written by yourself).

| tool                                                                        | language | tags                    | description                                                                                                                                                                                                                         |
| --------------------------------------------------------------------------- | -------- | ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)    | Python   | #subdomain_takeover     | Test a list of subdomains to find dangling DNS records. One of the most popular and accurate tools for automated testing for subdomain takeover. Supports a wide range of services to be checked.                                   |
| [DNS Reaper](https://github.com/punk-security/dnsReaper?tab=readme-ov-file) | Python   | #subdomain_takeover<br> | A fast subdomain takeover testing tool with a wealth of options. Works by fetching DNS records of a domain name and checking whether resources specified in records are active or not. Supports AWS Route53, Cloudflare, and Azure. |
| [Subjack](https://github.com/haccer/subjack)                                | Go       | #subdomain_takeover<br> | A subdomain takeover tool written in Go, designed to scan a list of subdomains concurrently and identify ones that can be hijacked. The repository is archived.                                                                     |

Online tools:
- [`dnsReaper web`](https://punksecurity.co.uk/dnsreaper/)




