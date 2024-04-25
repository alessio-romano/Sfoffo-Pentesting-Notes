# MySQL

## **Introduction**

> * MySQL is an open-source SQL relational database management system
> * MySQL runs port 3306 TCP by default
> * Often times, databases are stored in a single `.sql` file

***

## **MySQL Basic Commands**

| Command                                              | Description                                                                                                                                                |
| ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| mysql -u -p -h \<FQDN/IP>                            | Login to the MySQL server. Note: -p'password' without spaces                                                                                               |
| show variables like "secure\_file\_priv";            | Enumerate the secure file priv variable needed to enable reading/writing of files: NULL means no write permissions, FOLDERNAME means limited to the folder |
| SELECT "" INTO OUTFILE '/var/www/html/webshell.php'; | Write local file (webshell)                                                                                                                                |
| select LOAD\_FILE("/etc/passwd");                    | Read local file                                                                                                                                            |
| SELECT @@version                                     | Fingerprint MySQL with query output                                                                                                                        |
| SELECT SLEEP(5)                                      | Fingerprint MySQL with no output                                                                                                                           |

***

## **MySQL Database Interaction**

| Command                                                           | Description                                              |
| ----------------------------------------------------------------- | -------------------------------------------------------- |
| mysql -u root -h docker.hackthebox.eu -P 3306 -p                  | login to mysql database                                  |
| SHOW DATABASES                                                    | List available databases                                 |
| USE users                                                         | Switch to database                                       |
| CREATE TABLE logins (id INT, ...)                                 | Add a new table                                          |
| SHOW TABLES                                                       | List available tables in current database                |
| DESCRIBE logins                                                   | Show table properties and columns                        |
| INSERT INTO table\_name VALUES (value\_1,..)                      | Add values to table                                      |
| INSERT INTO table\_name(column2, ...) VALUES (column2\_value, ..) | Add values to specific columns in a table                |
| UPDATE table\_name SET column1=newvalue1, ... WHERE               | Update table values                                      |
| SELECT \* FROM table\_name                                        | Show all columns in a table                              |
| SELECT column1, column2 FROM table\_name                          | Show specific columns in a table                         |
| DROP TABLE logins                                                 | Delete a table                                           |
| ALTER TABLE logins ADD newColumn INT                              | Add new column                                           |
| ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn           | Rename column                                            |
| ALTER TABLE logins MODIFY oldColumn DATE                          | Change column datatype                                   |
| ALTER TABLE logins DROP oldColumn                                 | Delete column                                            |
| SELECT \* FROM logins ORDER BY column\_1                          | Sort by column                                           |
| SELECT \* FROM logins ORDER BY column\_1 DESC                     | Sort by column in descending order                       |
| SELECT \* FROM logins ORDER BY column\_1 DESC, id ASC             | Sort by two-columns                                      |
| SELECT \* FROM logins LIMIT 2                                     | Only show first two results                              |
| SELECT \* FROM logins LIMIT 1, 2                                  | Only show first two results starting from index 2        |
| SELECT \* FROM table\_name WHERE                                  | List results that meet a condition                       |
| SELECT \* FROM logins WHERE username LIKE 'admin%'                | List results where the name is similar to a given string |

***

## **SQL Injection**

Refer to the SQL Injection Notes
