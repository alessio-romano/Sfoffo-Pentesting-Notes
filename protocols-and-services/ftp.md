# FTP

## **Introduction**

> FTP is a clear-text protocol used to transfer files, which typically runs on TCP port 21.\
> There are different commands and status codes in FTP. Not all of these commands are consistently implemented on the server.\
> Usually, we need credentials to interact with a FTP server.

***

## **FTP Misconfigurations**

#### **FTP PUT Method**

* Whenever FTP allows the PUT method, there may be chances that the files can be accessed from a web application's webroot or any directory accessible via the web app
* In order terms, files uploaded through the FTP server can be accesses through the HTTP server
* This can be useful to **upload a reverse shell through the FTP server and running it through the HTTP Server**

#### **FTP Anonymous Access**

* When allowed, a server can offer anonymous FTP access.
* Since there are security risks associated with such a public FTP server, the options for users are usually limited.
* To authenticate using anonymous access: `ftp anonymous@server-ip` followed by any password

***

## **FTP Basic Interaction**

Connecting to ftp:

* `ftp <FQDN/IP>`
* `ftp username@ip`
* `nc -nv <FQDN/IP> 21`
* `telnet <FQDN/IP> 21`
* Interact with the FTP service on the target using encrypted connection:\
  `openssl s_client -connect <FQDN/IP>:21 -starttls ftp`
* Download all available files on the target FTP Server:\
  `wget -m --no-passive ftp://anonymous:anonymous@<target>`

#### **FTP Methods**

1. `connect` - Sets the remote host for file transfers.
2. `get` - Download a file from the ftp server.
3. `put` - Upload a local file to the ftp server.
4. `quit` - Exits ftp.
5. `status` - Shows the current status of tftp, including the current transfer mode (ascii or binary), connection status, time-out value, and so on.
6. `verbose` - Toggle verbose mode

***

## **FTP Authentication Bruteforcing**

1. Bruteforcing with Medusa: `medusa -u username -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp`
2. Bruteforcing with Hydra: `hydra -l username -P /usr/share/wordlists/rockyou.txt ftp://192.168.2.142`

***

## **FTP Useful Files**

* The **default configuration of vsFTPd** can be found in `/etc/vsftpd.conf`
* The file `/etc/ftpusers` is used to **deny certain users access** to the FTP service.

***

## **FTP Bounce Attack**

> An FTP bounce attack is a network attack that uses FTP servers to deliver outbound traffic to another device on the network.\
> The attacker uses a PORT command to trick the FTP connection into running commands and getting information from a device other than the intended server.

**Example:**

* Consider we are targetting an FTP Server FTP\_DMZ exposed to the internet.
* Another device within the same network, Internal\_DMZ, is not exposed to the internet.
* We can use the connection to the FTP\_DMZ server to scan Internal\_DMZ using the FTP Bounce attack and obtain information about the server's open ports.
* Then, we can use that information as part of our attack against the infrastructure.

**To perform a FTP Bounce Attack with Nmap:**\
`nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2`
