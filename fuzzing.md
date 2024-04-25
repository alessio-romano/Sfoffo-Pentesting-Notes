# Fuzzing

## **Introduction**

> Fuzz testing or Fuzzing is a software testing technique which basically consists in finding implementation bugs using malformed/semi-malformed data injection in an automated fashion. Fuzzing techniques can also be used to discover vhosts, subdomains and web content

## **Web Application Content Fuzzing**

| Command                                                                                           | Description       |
| ------------------------------------------------------------------------------------------------- | ----------------- |
| ffuf -w wordlist.txt:FUZZ -u http://SERVER\_IP:PORT/FUZZ                                          | Directory Fuzzing |
| gobuster dir -u https://server:port -w wordlist                                                   | Directory Fuzzing |
| ffuf -w wordlist.txt:FUZZ -u http://SERVER\_IP:PORT/indexFUZZ                                     | Extension Fuzzing |
| ffuf -w wordlist.txt:FUZZ -u http://SERVER\_IP:PORT/blog/FUZZ.php                                 | Page Fuzzing      |
| ffuf -w wordlist.txt:FUZZ -u http://SERVER\_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v | Recursive Fuzzing |

## **Sub-Domain Fuzzing**

| Command                                               | Description        |
| ----------------------------------------------------- | ------------------ |
| ffuf -w wordlist.txt:FUZZ -u https://FUZZ.server.com/ | Sub-domain Fuzzing |
| gobuster dns -d example.com -w wordlists.txt          | Sub-domain Fuzzing |

## **VHost Fuzzing**

| Command                                                                                                                                  | Description                         |
| ---------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| ffuf -w wordlist.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs xxx                                                | VHost Fuzzing                       |
| gobuster vhost -u https://example:port -w wordlist                                                                                       | Gobuster VHost Fuzzing              |
| gobuster vhost --url test.example --wordlist /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain | Better way - Gobuster Vhost Fuzzing |

## **HTTP GET/POST Parameter Fuzzing**

| Command                                                                                                                                                | Description              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------ |
| ffuf -w wordlist.txt:FUZZ -u http://server.com:PORT/admin/admin.php?FUZZ=key -fs xxx                                                                   | Parameter Fuzzing - GET  |
| ffuf -w wordlist.txt:FUZZ -u http://server.com:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx | Parameter Fuzzing - POST |
| ffuf -w ids.txt:FUZZ -u http://server.com:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx       | Parameter Value Fuzzing  |

***

## **Path traversal/File Inclusion Fuzzing**

| Command                                                                                                                                        | Description                |
| ---------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- |
| ffuf -w /path-to/burp-parameter-names.txt:FUZZ -u 'http://\<SERVER\_IP>:/index.php?FUZZ=value' -fs 2287                                        | Fuzz page parameters       |
| ffuf -w /path-to/LFI-Jhaddix.txt:FUZZ -u 'http://\<SERVER\_IP>:/index.php?language=FUZZ' -fs 2287                                              | Fuzz LFI payloads          |
| ffuf -w /path-to/default-web-root-directory-linux.txt:FUZZ -u 'http://\<SERVER\_IP>:/index.php?language=../../../../FUZZ/index.php' -fs 2287\` | Fuzz webroot path          |
| ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://\<SERVER\_IP>:/index.php?language=../../../../FUZZ' -fs 2287                                      | Fuzz server configurations |
