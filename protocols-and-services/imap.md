# IMAP

## **Introduction**

> By default, the Internet Message Access Protocol (IMAP) protocol works on Port 143 (unencrypted) or 993 (encrypted). IMAP allows online management of emails directly on the server and supports folder structures.\
> Thus, it is a network protocol for the online management of emails on a remote server.\
>

***

## **IMAP Basic Interaction Commands**

| Command                                                  | Description                             |
| -------------------------------------------------------- | --------------------------------------- |
| curl -k 'imaps://\<FQDN/IP>' --user :                    | Log in to the IMAPS service using cURL. |
| openssl s\_client -connect \<FQDN/IP>:imaps              | Connect to the IMAPS service.           |
| hydra -L users.txt -p validpassword -f 10.10.110.20 imap | Login Bruteforce with Hydra (IMAP)      |

***

## **IMAP Commands**

| Command                       | Description                                                                                               |
| ----------------------------- | --------------------------------------------------------------------------------------------------------- |
| 1 LOGIN username password     | User's login.                                                                                             |
| 1 LIST "" \*                  | Lists all directories.                                                                                    |
| 1 FETCH 1 BODY\[TEXT]         | list all contents of previously selected mail                                                             |
| 1 CREATE "INBOX"              | Creates a mailbox with a specified name.                                                                  |
| 1 DELETE "INBOX"              | Deletes a mailbox.                                                                                        |
| 1 RENAME "ToRead" "Important" | Renames a mailbox.                                                                                        |
| 1 LSUB "" \*                  | Returns a subset of names from the set of names that the User has declared as being active or subscribed. |
| 1 SELECT INBOX                | Selects a mailbox so that messages in the mailbox can be accessed.                                        |
| 1 UNSELECT INBOX              | Exits the selected mailbox.                                                                               |
| 1 FETCH all                   | Retrieves data associated with a message in the mailbox.                                                  |
| 1 CLOSE                       | Removes all messages with the Deleted flag set.                                                           |
| 1 LOGOUT                      | Closes the connection with the IMAP server.                                                               |
