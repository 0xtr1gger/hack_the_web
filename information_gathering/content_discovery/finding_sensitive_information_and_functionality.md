## Internet Archives

Web archives, such as the Wayback Machine, store historical snapshots of websites. This is useful for security investigations, as it allows you to examine previous versions of a target website to identify changes and potentially uncover sensitive locations that were hidden at the time of the investigation but are still accessible for anyone who manages to find them.

Internet archive resources:

- [`Wayback Machine`](https://web.archive.org/)
- [`Internet Archive`](https://archive.org/)
- [`Archive.today`](https://archive.ph/)

Hints on what to search for:

- Scrape archived `robots.txt` files. Old endpoints not used since long ago may still work and contain interesting functionality to explore.

- Analyze archived versions of the target website, searching for `GET`/`POST` parameter names and values. You may find interesting parameters, such as hidden form fields, that have been removed from the current version of HTML on the website; however, the back-end code that handles them might still be present.

- Search for old API endpoints. They might still work. 

- Archives can be helpful in finding sensitive information such as API keys, authentication credentials, and more. Inspect the source: look for comments, `<meta>` tags, and the like; enumerate archived pages and try to find something interesting there.

- Search for sensitive files within archived versions of websites: they might still be present. Pay attention to:
	- Backup files: `.bak`, `.old`, `.backup`, etc.
	- Compressed files: `.tar`, `.zip`, `.gz`, etc.
	- Configuration files: `.config`, `.cf`, `.cfg`, `.conf`, `.xml`, `.json`, etc.

- An obvious target for investigations are admin interfaces and other powerful functionality. This may hint at the present location of these pages.

- Past vulnerabilities may suggest what kinds of flaws the application could contain in the present, as people, including web developers, tend to make the same mistakes.

More information for finding sensitive files in web applicaitons can be found [here].

There are many tools that are designed to automate retrieval of archived pages for a given domain, including:

| tool                                                                                 | language | tags                                      | description                                                                                                                                                                                                                   |
| ------------------------------------------------------------------------------------ | -------- | ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [waybackurls](https://github.com/tomnomnom/waybackurls)                              | Go       | #archive_search                           | Given a list of domains, fetches all relevant URLs from the Wayback Machine archive.                                                                                                                                          |
| [waymore](https://github.com/xnl-h4ck3r/waymore)                                     | Python   | #archive_search                           | The idea behind `waymore` is to find even more links from the Wayback Machine than other existing tools. It fetches URLs not only from Wayback Machine, but also from Common Crawl, Alien Vault OTX, URLScan and Virus Total. |
| [gau](https://github.com/lc/gau)                                                     | Go       | #archive_search <br>#content_discovery    | Retrieves known URLs from AlienVault's [Open Threat Exchange](https://otx.alienvault.com), the Wayback Machine, Common Crawl, and URLScan for any given domain.                                                               |
| [paramspider](https://github.com/devanshbatham/ParamSpider)                          | Python   | #archive_search<br>#content_discovery<br> | Extracts URLs associated with any domain or a list of domains from Wayback archives.                                                                                                                                          |
| [waybackrobots.py](https://gist.github.com/mhmdiaa/2742c5e147d49a804b408bfed3d32d07) | Python   | #archive_search                           | A script that automates searching for archived `robots.txt` files.                                                                                                                                                            |
| [waybackpack](https://github.com/jsvine/waybackpack)                                 | Python   | #archive_search                           | A command-line tool that allows you to download the entire Wayback Machine archive for a given URL.                                                                                                                           |

N.B.: Web archives are helpful in both finding sensitive files and directories, and in subdomain enumeration. To extract subdomains from a list of URLs retrieved from a web archive, apply the `unfurl` tool to remove URL schemes and paths, and then use the `sort` command to remove duplicates and sort the obtained subdomains alphabetically:

```bash
cat URLs.txt | unfurl -u domains > subdomains.txt
sort --output subdomains.txt -u subdomains.txt
```
#### `waybackulrs`

Installation:

```bash
go install github.com/tomnomnom/waybackurls@latest

# or
git clone https://github.com/tomnomnom/waybackurls
cd waybackurls
go build .
sudo mv waybackurls /usr/local/bin/
```

Retrieve all archived pages under the specified domain:

```bash
echo target.com | waybackurls > output.txt
```

By default, `waybackurls` retrieves URLs from subdomains of the specified domain as well. To disable it, use the `-no-subs` option:

```bash
echo target.com | waybackurls -no-subs > output.txt 
```

The tool can also display dates of fetch of URLs, as well as crawled versions, with the `-dates` and `-get-versions` options, respectively.

```bash
echo target.com | waybackurls -dates -no-subs > output.txt 
```

```
2023-06-08T15:14:48Z https://redacted.org/.well-known/ai-plugin.json
2023-02-17T09:43:20Z https://redacted.org/.well-known/apple-app-site-association
2023-06-08T15:00:46Z https://redacted.org/.well-known/assetlinks.json
2023-06-08T14:54:29Z https://redacted.org/.well-known/dnt-policy.txt
2024-04-04T23:47:10Z https://redacted.org/.well-known/en
2023-07-01T13:57:12Z https://redacted.org/.well-known/en,%20de,%20pl,%20es,%20fr
2023-06-08T14:48:30Z https://redacted.org/.well-known/gpc.json
2023-06-08T14:52:17Z https://redacted.org/.well-known/nodeinfo
2023-06-08T15:13:19Z https://redacted.org/.well-known/openid-configuration
2023-06-08T15:34:25Z https://redacted.org/.well-known/security.txt
2023-06-08T14:50:52Z https://redacted.org/.well-known/trust.txt
. . . 
```
#### `waymore`

Installation as a Python library:

```bash
pip install waymore
```

Installation:

```bash
git clone https://github.com/xnl-h4ck3r/waymore
cd ./waymore/waymore
python3 waymore.py
```

Usage:

```bash
python3 waymore.py -i [--input] target.com
```

#### `gau`

Installation:

```bash
go install github.com/lc/gau/v2/cmd/gau@latest
gau --version

# or
git clone https://github.com/lc/gau.git
cd gau/cmd/gau
go build .
sudo mv gau /usr/local/bin/
gau --version
```

To fetch all URLs related to the target domain:

```bash
gau --threads 5 --subs --o output.txt target.com
```

| Option      | Description                          |
| ----------- | ------------------------------------ |
| `--threads` | Number of threads. Default `1`.      |
| `--subs`    | Include subdomains of target domain. |
| `--o`       | Output file.                         |

```
http://target.com/
https://target.com/robots.txt
http://subdomain.target.com/
https://www.target.com/
https://www.target.com/?ref=truth11.com
https://www.target.com/careers
https://www.target.com/cdn-cgi/l/email-protection
https://www.target.com/contact-us
https://www.target.com/forms/field-operations
https://www.target.com/forms/integrations
https://www.target.com/orb
...
```
