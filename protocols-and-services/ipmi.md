# IPMI

## **Introduction**

> * IPMI is a set of standardized specifications for hardware-based host management systems used for system management and monitoring
> * IPMI provides sysadmins with the ability to manage and monitor systems even if they are powered off or in an unresponsive state using a direct network connection to the system's hardware without requiring any form of authentication
> * IPMI can also be used for remote upgrades to systems without requiring physical access to the target host.
> * It can also be used for querying inventory information, reviewing hardware logs, and alerting using SNMP
> * **Source:** [HacktheBox Academy](https://academy.hackthebox.com/module/112/section/1245)

***

## **IPMI Commands**

| Command                                       | Description             |
| --------------------------------------------- | ----------------------- |
| msf6 auxiliary(scanner/ipmi/ipmi\_version)    | IPMI version detection. |
| msf6 auxiliary(scanner/ipmi/ipmi\_dumphashes) | Dump IPMI hashes.       |
