# Microsoft IIS

## **Introduction**

> * Internet Information Services (IIS) for Windows Server is a flexible, secure and manageable Web server for hosting anything on the Web.
> * From media streaming to web applications, IIS's scalable and open architecture is ready to handle the most demanding tasks.

***

## **Microsoft IIS Tilde Enumeration**

> * IIS tilde directory enumeration is a technique utilised to uncover hidden files, directories, and short file names on some versions of Microsoft Internet Information Services (IIS) web servers.
> * This method takes advantage of a specific vulnerability in IIS, resulting from how it manages short file names within its directories.
> * The tilde (`~`) character, followed by a sequence number, signifies a short file name in a URL.
> * Hence, if someone determines a file or folder's short file name, they can exploit the tilde character and the short file name in the URL to access sensitive data or hidden resources.
> * Assume the server contains a hidden directory named SecretDocuments.
> * When a request is sent to `http://example.com/~s`, the server replies with a `200 OK` status code, revealing a directory with a short name beginning with "s".
> * The enumeration process continues by appending more characters
> * Manually sending HTTP requests for each letter of the alphabet can be a tedious process.
> * Fortunately, there is a tool called `IIS-ShortName-Scanner` that can automate this task.

***

## **IIS Tilde Automatic Enumeration**

**IIS ShortName Scanner:**

* GitHub Resource: [https://github.com/irsdl/IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner)
* Note: to use `IIS-ShortName-Scanner`, you will need to install Oracle Java.
* Refer to: [https://ubuntuhandbook.org/index.php/2022/03/install-jdk-18-ubuntu/](https://ubuntuhandbook.org/index.php/2022/03/install-jdk-18-ubuntu/)

**Others:**

* [https://github.com/sw33tLie/sns](https://github.com/sw33tLie/sns)
* [https://github.com/bitquark/shortscan](https://github.com/bitquark/shortscan)
