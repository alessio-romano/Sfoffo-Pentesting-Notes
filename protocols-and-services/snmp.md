# SNMP

## **Introduction**

> * Simple Network Management Protocol (SNMP) is a protocol for monitoring different devices in the network
> * It can contain different information about devices, including `logs` and `credentials`
> * By default, SNMNP runs on port 161 UDP
> * SNMP often requires a "community string" to authenticate

***

## **SNMP Enumeration**

| Command                                          | Description                                         |
| ------------------------------------------------ | --------------------------------------------------- |
| snmpwalk -v2c -c \<FQDN/IP>                      | Querying OIDs using snmpwalk.                       |
| onesixtyone -c community-strings.list \<FQDN/IP> | Bruteforcing community strings of the SNMP service. |
| braa @\<FQDN/IP>:.1.\*                           | Bruteforcing SNMP service OIDs.                     |
| snmp-check -c                                    | Enumerate SNMP                                      |

### SNMP Enumeration using snmpwalk

The following examples are given using the `public` community string.\
Replace it with your community string if needed.

1. List all Windows Users:\
   `snmpwalk -v <snmp-version> -c <string> <IP> 1.3.6.1.4.1.77.1.2.25`
2. List all running processes: \
   `snmpwalk-v <snmp-version> -c <string> <IP> 1.3.6.1.2.1.25.4.2.1.2`
3. List all installed software:\
   `snmpwalk -v <snmp-version> -c <string> <IP> 1.3.6.1.2.1.25.6.3.1.2`
4. List TCP listening ports:\
   `snmpwalk -v <snmp-version> -c <string> <IP> 1.3.6.1.2.1.6.13.1.3`
5. Enumerate all info (might be too verbose):\
   `snmpwalk -v <snmp-version> -c <community-string> <IP> .1`&#x20;
6. Get extended objects (might reveal some otherwise hidden info):\
   `snmpwalk -v <snmp-version> -c <string> <IP> NET-SNMP-EXTEND-MIB::nsExtendObjects`&#x20;
