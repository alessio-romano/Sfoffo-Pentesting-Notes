# POP3

## **Introduction**

> * There are 3 different versions of POP, but POP3 is the mostly used one.
> * POP3 runs on TCP ports 110(unencrypted) and 995(encrypted) by default.
> * Post Office Protocol (POP) is a protocol that extracts and retrieves email from a remote mail server for access by the host machine.
> * POP3 provides users the ability to fetch and receive email

***

## **POP3 Basic Interaction**

| Command                                                 | Description                        |
| ------------------------------------------------------- | ---------------------------------- |
| openssl s\_client -connect \<FQDN/IP>:pop3s             | Connect to the POP3s service.      |
| hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3 | Login Bruteforce with Hydra (POP3) |

***

## **POP3 Commands**

| Command       | Description                                                 |
| ------------- | ----------------------------------------------------------- |
| USER username | Identifies the user.                                        |
| PASS password | Authentication of the user using its password.              |
| STAT          | Requests the number of saved emails from the server.        |
| LIST          | Requests from the server the number and size of all emails. |
| RETR id       | Requests the server to deliver the requested email by ID.   |
| DELE id       | Requests the server to delete the requested email by ID.    |
| CAPA          | Requests the server to display the server capabilities.     |
| RSET          | Requests the server to reset the transmitted information.   |
| QUIT          | Closes the connection with the POP3 server.                 |
