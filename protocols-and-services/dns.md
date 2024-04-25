# DNS

## **Introduction**

> DNS Typically runs on port 53 UDP but it can also run on TCP\
> DNS translates domain names to IP addresses\
> Useful resources:
>
> * [https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns](https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns)
> * [https://academy.hackthebox.com/module/112/section/1069](https://academy.hackthebox.com/module/112/section/1069)

## **DNS Records**

| DNS Record | Description                                                                                                                                                      |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A          | Returns an IPv4 address of the requested domain as a result.                                                                                                     |
| AAAA       | Returns an IPv6 address of the requested domain.                                                                                                                 |
| MX         | Returns the responsible mail servers as a result.                                                                                                                |
| NS         | Returns the DNS servers (nameservers) of the domain.                                                                                                             |
| TXT        | This record can contain various information. For example, it can be used to validate the Google Search Console or validate SSL certificates.                     |
| CNAME      | This record serves as an alias. If the domain www.hackthebox.eu should point to the same IP, and we create an A record for one and a CNAME record for the other. |
| PTR        | The PTR record works the other way around (reverse lookup). It converts IP addresses into valid domain names.                                                    |
| SOA        | Provides information about the corresponding DNS zone and email address of the administrative contact.                                                           |

## **Basic Interaction**

| Command                         | Description                                              |
| ------------------------------- | -------------------------------------------------------- |
| dig ns \<domain.tld> @dns-ip    | NS request to the specific nameserver.                   |
| dig any \<domain.tld> @dns-ip   | ANY request to the specific nameserver.                  |
| dig axfr \<domain.tld> @dns-ip  | AXFR (ZONE TRANSFER) request to the specific nameserver. |
| fierce --domain zonetransfer.me | Use fierce to scan for Zone Transfers                    |

## **Sub-Domain Enumeration:**

There are different tools to perform subdomain enumeration:

1. `./subfinder -d test.com -v`
2. `sublist3r.py -d test.com`
3. `./subbrute test.com -s ./names.txt -r ./resolvers.txt`

**Subdomain Fuzzing:**

1. `ffuf -w wordlist.txt:FUZZ -u https://FUZZ.server.com/`
2. `gobuster dns -d example.com -w wordlists.txt`

**VHost Fuzzing**

1. `ffuf -w wordlist.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs <num>`
2. `gobuster vhost --url test.example --wordlist /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain`

**Subdomain Bruteforcing:**

```
Option (1): dnsenum --dnsserver <dns-ip> --enum -p 0 -s 0 -o found_subdomains.txt -f ~/subdomains.list <domain.tld>

Option (2): for sub in $(cat path/to/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 \| grep -v ';\|SOA' \| sed -r '/^\s*$/d' \| grep $sub \| tee -a subdomains.txt;done
```
