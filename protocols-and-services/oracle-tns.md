# Oracle TNS

## **Introduction**

> * Communication protocol that facilitates communication between Oracle databases and applications over networks
> * Solution for managing large, complex databases, typically in the healthcare, finance, and retail industries.
> * It has a built-in encryption mechanism that ensures the security of data transmitted.
> * Runs on TCP Port 1521 by default

***

## **Oracle TNS - Basic Commands**

| Command                                                                                        | Description                                                                                             |
| ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| ./odat.py all -s \<FQDN/IP>                                                                    | Perform a variety of scans to gather information about the Oracle database services and its components. |
| sqlplus /@\<FQDN/IP>/                                                                          | Log in to the Oracle database.                                                                          |
| sqlplus username/password@10.129.204.235/XE as sysdba                                          | Log in to the Oracle database with sysdba privileges                                                    |
| ./odat.py utlfile -s \<FQDN/IP> -d -U -P --sysdba --putFile C:\insert\path file.txt ./file.txt | Upload a file with Oracle RDBMS.                                                                        |
| sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute                           | Nmap SID Bruteforcing                                                                                   |

***

## **Oracle RDBMS Interaction Commands**

| Command                               | Description                                   |
| ------------------------------------- | --------------------------------------------- |
| select table\_name from all\_tables;  | List all available tables in current database |
| select name, password from sys.user$; | Extract password hashes                       |
