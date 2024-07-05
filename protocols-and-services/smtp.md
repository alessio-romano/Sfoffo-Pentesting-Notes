# SMTP

## **Introduction**

> * The Simple Mail Transfer Protocol (SMTP) is a protocol for sending emails in an IP network
> * SMTP is often combined with the IMAP or POP3 protocols, which can fetch emails and send emails.
> * SMTP runs on port 25 UDP by default
> * Newer SMTP servers also use other ports such as TCP 587

***

## **SMTP Enumeration**

| Command                                                                         | Description                                                     |
| ------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| telnet \<FQDN/IP> 25 followed by `EHLO nameserver.htb` or `HELO nameserver.htb` | Check connection to SMTP                                        |
| `Test-NetConnection -Port 25 192.168.50.8`                                      | Check connection to SMTP (Windows)                              |
| smtp-user-enum -M VRFY -u root -t 192.168.1.25                                  | Enumerate SMTP user "root" using the VRFY method (if available) |
| sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v                        | SMTP Open Relay server enumeration via nmap script              |

***

## **SMTP Open Relay**

> * An open relay is a SMTP server improperly configured to allow an unauthenticated email relay.
> * A SMTP Open Relay allows mail from any source to be transparently re-routed through the open relay server.
> * This behavior masks the source of the messages and makes it look like the mail originated from the open relay server.
> * Useful for phishing purposes
