# HTTP Verb Tampering

## **Introduction**

> * An HTTP Verb Tampering attack exploits web servers that accept many HTTP verbs and methods.
> * This can be exploited by sending malicious requests using **unexpected HTTP methods**
> * This allows bypassing the web application's authorization mechanisms or even bypassing its security controls.

***

## **HTTP Verbs**

1. `GET`: Request data from a specified resource
2. `POST`: Send data to a server to create/update a resource
3. `HEAD`: Identical to a GET request, but its response only contains the `headers`, without the response body
4. `PUT`: Writes the request payload to the specified location
5. `DELETE`: Deletes the resource at the specified location
6. `OPTIONS`: Shows different options accepted by a web server, like accepted HTTP verbs
7. `PATCH`: Apply partial modifications to the resource at the specified location

***

## **HTTP Verbs Enumeration**

To identify an HTTP Verb Tampering Vulnerability:

1. **Insecure configuration** such as: `<Limit GET POST> require valid-user </Limit>` This allows any method other than GET and POST to bypass any user validity checks
2. **Insecure coding** such as a PHP file with an explicit declaration of an HTTP Method, e.g. `if(..., $_GET["code"]`. This allows any method other than GET to bypass the if check
3. **Show all available HTTP Methods**: `curl -i -X OPTIONS http://SERVER:PORT`

***

## **Examples of HTTP Verb Tampering**

1. **Bypassing Basic Authentication:** sometimes it's possible to bypass HTTP Basic Auth by simply changing the HTTP verb
2. **Bypassing Security Filters:** sometimes it's possible to bypass security filters whenever an error message as "cannot GET _resourcename_" is shown
3. **Forcing Errors:** sometimes it's possible to show error logs by just using unexpected HTTP Verbs
