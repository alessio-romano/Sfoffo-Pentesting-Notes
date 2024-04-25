# Splunk

## **Introduction**

> * Splunk is a `SIEM tool` prevalent in `internal networks`
> * The Splunk web server runs by default on `port 8000`.
> * On older versions of Splunk, the default credentials are `admin:changeme` (displayed on the login page)
> * The latest version of Splunk sets credentials during the installation process.
> * If the default credentials do not work, it is worth checking for `common weak passwords` such as `admin`, `Welcome`, `Welcome1`, `Password123`, etc.
> * The Splunk Enterprise trial converts to a free version after `60 days`
> * The `free version` of Splunk does not have any form of authentication
> * `Approach`: The biggest focus of Splunk during an assessment would be weak or null authentication because admin access to Splunk gives us the ability to deploy custom applications that can be used to quickly compromise a Splunk server and possibly other hosts in the network depending on the way Splunk is set up.

***

## **Splunk RCE \[Authenticated]**

> * We can gain remote code execution on Splunk by creating a custom application to run Python, PowerShell Batch or Bash scripts
> * Use [https://github.com/0xjpuff/reverse\_shell\_splunk](https://github.com/0xjpuff/reverse\_shell\_splunk)
> * Follow the instructions in the README of that repository
