# 🔍 Information Gathering

## **Passive Information Gathering & OSINT**

* These techniques refer to gaining information from publicly available sources
* By doing so, the attacker gains information about the target, without any type of active scanning
* This ensures that the target will never be aware that we are obtaining information about it, since there is no form of direct interaction

External Resources:

1. [https://www.cheatsheet.wtf/OSINT/](https://www.cheatsheet.wtf/OSINT/)
2. [https://www.compass-security.com/fileadmin/Research/White\_Papers/2017-01\_osint\_cheat\_sheet.pdf](https://www.compass-security.com/fileadmin/Research/White\_Papers/2017-01\_osint\_cheat\_sheet.pdf)
3. [https://bigdata-ir.com/wp-content/uploads/2021/02/OSINT\_Packet\_2019.pdf](https://bigdata-ir.com/wp-content/uploads/2021/02/OSINT\_Packet\_2019.pdf)

***

### Google Dorks

Google can be a powerful tool for penetration testing and bug-bounty hunting.\
Google's crawling capabilities can help us find exposed files, scripts and other critical resources in web applications.

This [blogpost](https://www.freecodecamp.org/news/google-dorking-for-pentesters-a-practical-tutorial/) can be useful if you need to learn more about google dorks.

You can also refer to the following:

* [https://www.exploit-db.com/google-hacking-database](https://www.exploit-db.com/google-hacking-database)
* [https://pentest-tools.com/information-gathering/google-hacking](https://pentest-tools.com/information-gathering/google-hacking)

<details>

<summary>Generic Queries</summary>

`site:*.target.com intext:uncaught`

`site:*.target.com intext:error`

`site:*.target.com intext:parameter`

`site:*.target.com intext:missing`

`site:*.target.com intext:"stack trace"`

`site:*.target.com intext:php`

`site:*.target.com intext:jsp`

`site:*.target.com intext:asp`

`site:*.target.com intext:include_path`

`site:*.target.com intext:undefined`

`site:*.target.com intext:sql`

`site:*.target.com intext:invalid`

`site:*.target.com intext:exception`

`site:*.target.com intext:fatal`

`site:*.target.com intext:CONFIG`

`site:*.target.com intext:login`

`site:*.target.com intitle:"index of"`

`site:*.target.com inurl:prod`

`site:*.target.com inurl:&`

`site:*.target.com inurl:dev`

`site:*.target.com inurl:staging`

`site:*.target.com inurl:stg`

`site:*.target.com inurl:debug`

`site:*.target.com inurl:admin`

`site:*.target.com inurl:internal`

</details>

<details>

<summary>Apache Services</summary>

`site:*.target.com intitle:"apache tomcat/"`

`site:*.target.com "Apache Tomcat examples"`

`site:*.target.com intext:"apache"`

`site:*.target.com intitle:"Solr Admin"`

`site:*.target.com intext:"This is the default welcome page used to test the correct operation of the Apache2 server"`

`site:*.target.com intitle:"index of" "powered by apache "`

`site:*.target.com intext:"Apache server status for"`

`site:*.target.com intitle:"Apache2 Ubuntu Default Page: It works"`

`site:*.target.com intitle:"WAMPSERVER homepage" "Server Configuration" "Apache Version"`

`site:*.target.com intitle:"Test Page for the Apache HTTP Server"`

</details>

<details>

<summary>Files</summary>

`site:*.target.com ext:txt`

`site:*.target.com ext:php`

`site:*.target.com ext:php5`

`site:*.target.com ext:phtml`

`site:*.target.com ext:xhtml`

`site:*.target.com ext:key`

`site:*.target.com ext:pem`

`site:*.target.com ext:ovpn`

`site:*.target.com ext:log`

`site:*.target.com ext:asp`

`site:*.target.com ext:aspx`

`site:*.target.com ext:jsp`

`site:*.target.com ext:dat`

`site:*.target.com ext:ovpn`

`site:*.target.com ext:yml`

`site:*.target.com ext:bak`

`site:*.target.com ext:zip`

`site:*.target.com ext:yaml`

`site:*.target.com ext:json`

`site:*.target.com ext:xml`

`site:*.target.com ext:env`

`site:*.target.com ext:conf`

`site:*.target.com ext:ini`

`site:*.target.com ext:cfg`

`site:*.target.com ext:cgi`

`site:*.target.com ext:ccm`

`site:*.target.com ext:sql`

`site:*.target.com ext:cdx`

`site:*.target.com ext:ics`

</details>

<details>

<summary>GraphQL queries</summary>

`site:*.target.com intext:"GRAPHQL_PARSE_FAILED"`

`site:*.target.com intext:"GRAPHQL_VALIDATION_FAILED"`

`site:*.target.com intext:"BAD_USER_INPUT"`

`site:*.target.com intext:"UNAUTHENTICATED"`

`site:*.target.com intext:"FORBIDDEN"`

`site:*.target.com intext:"PERSISTED_QUERY_NOT_FOUND"`

`site:*.target.com intext:"PERSISTED_QUERY_NOT_SUPPORTED"`

`site:*.target.com intext:"INTERNAL_SERVER_ERROR"`

</details>

***

### **Domain Information using Crt.sh & Shodan**

1. Output and Download JSON:\
   `curl -s https://crt.sh/\?q\=test.com\&output\=json | jq .`
2. Filter JSON by subdomains:\
   `curl -s https://crt.sh/\?q\=test.com\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u`
3. Make an ip-address wordlist:\
   `for i in $(cat subdomainlist);do host $i | grep "has address" | grep [test.com](http://test.com/) | cut -d" " -f4 >> ip-addresses.txt;done`
4. Run shodan on those ip addresses:\
   `for i in $(cat ip-addresses.txt);do shodan host $i;done`

***

### **Passive Domain Enumeration**

| Resource/Command                                                                                                   | Description                                                                                    |
| ------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------- |
| VirusTotal                                                                                                         | https://www.virustotal.com/gui/home/url                                                        |
| Censys                                                                                                             | https://censys.io/                                                                             |
| Crt.sh                                                                                                             | https://crt.sh/                                                                                |
| curl -s https://sonar.omnisint.io/subdomains/{domain} \| jq -r '.\[]' \| sort -u                                   | All subdomains for a given domain.                                                             |
| curl -s https://sonar.omnisint.io/tlds/{domain} \| jq -r '.\[]' \| sort -u                                         | All TLDs found for a given domain.                                                             |
| curl -s https://sonar.omnisint.io/all/{domain} \| jq -r '.\[]' \| sort -u                                          | All results across all TLDs for a given domain.                                                |
| curl -s https://sonar.omnisint.io/reverse/{ip} \| jq -r '.\[]' \| sort -u                                          | Reverse DNS lookup on IP address.                                                              |
| curl -s https://sonar.omnisint.io/reverse/{ip}/{mask} \| jq -r '.\[]' \| sort -u                                   | Reverse DNS lookup of a CIDR range.                                                            |
| curl -s "https://crt.sh/?q=${TARGET}\&output=json" \| jq -r '.\[] \| "(.name\_value)\n(.common\_name)"' \| sort -u | Certificate Transparency.                                                                      |
| cat sources.txt \| while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}-${TARGET}";done      | Searching for subdomains and other information on the sources provided in the source.txt list. |
| https://searchdns.netcraft.com/                                                                                    | Search public information about a hostname using netcraft                                      |

***

### **Passive Infrastructure Identification**

| Resource/Command                                     | Description                                                |
| ---------------------------------------------------- | ---------------------------------------------------------- |
| Netcraft                                             | https://www.netcraft.com/                                  |
| WayBackMachine                                       | http://web.archive.org/                                    |
| WayBackURLs                                          | https://github.com/tomnomnom/waybackurls                   |
| waybackurls -dates https://$TARGET > waybackurls.txt | Crawling URLs from a domain with the date it was obtained. |

***

## **Active Information Gathering**

* By using active scans against the target, we can gain more (reliable) information about it
* Whenever we are executing external scans, nmap and many other different tools can help us gain a lay of the land of the target surface

***

### **Protocols and Services Footprinting with NMAP**

* Scanning a target with nmap may reveal services, open ports, service versions, operating system and so on
* After gaining a lay of the land of the protocols and services granted by the target, refer to the Protocols and Services Notes for more information

***

**NMAP Scanning Options**

| Nmap Option          | Description                                                                                                          |
| -------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `10.10.10.0/24`      | Target network range.                                                                                                |
| `-sn`                | Disables port scanning.                                                                                              |
| `-Pn`                | Disables ICMP Echo Requests                                                                                          |
| `-n`                 | Disables DNS Resolution.                                                                                             |
| `-PE`                | Performs the ping scan by using ICMP Echo Requests against the target.                                               |
| `--packet-trace`     | Shows all packets sent and received.                                                                                 |
| `--reason`           | Displays the reason for a specific result.                                                                           |
| `--disable-arp-ping` | Disables ARP Ping Requests.                                                                                          |
| `--top-ports=<num>`  | Scans the specified top ports that have been defined as most frequent.                                               |
| `-p-`                | Scan all ports.                                                                                                      |
| `-p22-110`           | Scan all ports between 22 and 110.                                                                                   |
| `-p22,25`            | Scans only the specified ports 22 and 25.                                                                            |
| `-F`                 | Scans top 100 ports.                                                                                                 |
| `-sS`                | Performs an TCP SYN-Scan.                                                                                            |
| `-sA`                | Performs an TCP ACK-Scan. Note: best for firewall and ids/ips evasion                                                |
| `-sU`                | Performs an UDP Scan.                                                                                                |
| `-sV`                | Scans the discovered services for their versions.                                                                    |
| `-sC`                | Perform a Script Scan with scripts that are categorized as "default".                                                |
| `-sL`                | List Scan - simply list targets to scan - useful to understand which targets are reachable                           |
| `--script <script>`  | Performs a Script Scan by using the specified scripts.                                                               |
| `-O`                 | Performs an OS Detection Scan to determine the OS of the target.                                                     |
| `-A`                 | Performs OS Detection, Service Detection, and traceroute scans.                                                      |
| `-D RND:5`           | Sets the number of random Decoys that will be used to scan the target. Note: useful for firewall and ids/ips evasion |
| `-e`                 | Specifies the network interface that is used for the scan.                                                           |
| `-S 10.10.10.200`    | Specifies the source IP address for the scan.                                                                        |
| `-g`                 | Specifies the source port for the scan.                                                                              |
| `--dns-server <ns>`  | DNS resolution is performed by using a specified name server.                                                        |

***

**NMAP Output Options**

| Nmap Option    | Description                                                                       |
| -------------- | --------------------------------------------------------------------------------- |
| `-oA filename` | Stores the results in all available formats starting with the name of "filename". |
| `-oN filename` | Stores the results in normal format with the name "filename".                     |
| `-oG filename` | Stores the results in "grepable" format with the name of "filename".              |
| `-oX filename` | Stores the results in XML format with the name of "filename".                     |

***

**NMAP Performance Options**

| Nmap Option                  | Description                                                     |
| ---------------------------- | --------------------------------------------------------------- |
| `--max-retries <num>`        | Sets the number of retries for scans of specific ports.         |
| `--stats-every=5s`           | Displays scan's status every 5 seconds.                         |
| `-v/-vv`                     | Displays verbose output during the scan.                        |
| `--initial-rtt-timeout 50ms` | Sets the specified time value as initial RTT timeout.           |
| `--max-rtt-timeout 100ms`    | Sets the specified time value as maximum RTT timeout.           |
| `--min-rate 300`             | Sets the number of packets that will be sent simultaneously.    |
| `-T <0-5>`                   | Specifies the specific timing template. \[0=paranoid, 5=insane] |

***

### **Vhosts, Subdomain and Web Content Fuzzing**

* Fuzz testing or Fuzzing is a Black Box software testing technique, which basically consists in finding implementation bugs using malformed/semi-malformed data injection in an automated fashion.
* Fuzzing techniques can also be used to discover vhosts, subdomains and web content
* Refer to the Fuzzing Notes for more information

***

### **Active Infrastructure Identification**

| Resource/Command                                                        | Description                                                |
| ----------------------------------------------------------------------- | ---------------------------------------------------------- |
| curl -I "http://${TARGET}"                                              | Display HTTP headers of the target webserver.              |
| whatweb -a https://www.facebook.com -v                                  | Technology identification.                                 |
| Wappalyzer                                                              | https://www.wappalyzer.com/                                |
| wafw00f -v https://$TARGET                                              | WAF Fingerprinting.                                        |
| Aquatone                                                                | https://github.com/michenriksen/aquatone                   |
| cat subdomain.list \| aquatone -out ./aquatone -screenshot-timeout 1000 | Makes screenshots of all subdomains in the subdomain.list. |

***

### **Active Subdomain Enumeration**

| Resource/Command                                                                                          | Description                                                                |
| --------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| HackerTarget                                                                                              | https://hackertarget.com/zone-transfer/                                    |
| SecLists                                                                                                  | https://github.com/danielmiessler/SecLists                                 |
| nslookup -type=any -query=AXFR $TARGET nameserver.target.domain                                           | Zone Transfer using Nslookup against the target domain and its nameserver. |
| gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster\_${TARGET}.txt" | Bruteforcing subdomains.                                                   |
| dnsrecon -d example.com -D subdomainwordlist.txt -t brt                                                   | Subdomain bruteforcing using dnsrecon                                      |
| dnsenum example.com                                                                                       | Automated enumeration using dnsenum                                        |

### **DNS Enumeration**

| Command                           | Description                                        |
| --------------------------------- | -------------------------------------------------- |
| nslookup $TARGET                  | Identify the A record for the target domain.       |
| nslookup -query=A $TARGET         | Identify the A record for the target domain.       |
| dig $TARGET @\<nameserver/IP>     | Identify the A record for the target domain.       |
| dig a $TARGET @\<nameserver/IP>   | Identify the A record for the target domain.       |
| nslookup -query=PTR               | Identify the PTR record for the target IP address. |
| dig -x @\<nameserver/IP>          | Identify the PTR record for the target IP address. |
| nslookup -query=ANY $TARGET       | Identify ANY records for the target domain.        |
| dig any $TARGET @\<nameserver/IP> | Identify ANY records for the target domain.        |
| nslookup -query=TXT $TARGET       | Identify the TXT records for the target domain.    |
| dig txt $TARGET @\<nameserver/IP> | Identify the TXT records for the target domain.    |
| nslookup -query=MX $TARGET        | Identify the MX records for the target domain.     |
| dig mx $TARGET @\<nameserver/IP>  | Identify the MX records for the target domain.     |
