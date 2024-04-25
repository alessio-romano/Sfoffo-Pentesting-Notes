# Insecure Direct Object References (IDOR)

## **Introduction**

> * IDOR refers to the ability to interact directly with object by using a reference to their identifier
> * An example of IDOR is whenever a web application uses a guessable id value that can be directly modified by the user (e.g. an id in the URL)
> * As web applications store users' files and information, they may use sequential numbers or user IDs to identify each item.
> * IDOR can lead to accessing data that should not be accessible by attackers.
> * What makes this attack very common is essentially the lack of a solid access control system on the back-end.
> * IDOR _"becomes"_ BROKEN ACCESS CONTROL whenever a user can access other objects which he doesn't have permissions for (e.g. other user's data or admin data)

***

## **Detecting potential IDOR Vulnerabilities**

1. Example: `GET` request with a specific reference to an object by using `?id=NUMBER`
2. Example: `POST` request with a specific reference (in its body) to an object by using `?id=NUMBER`
3. Example: `POST` request with specific user-permissions-related parameters such as `user role o permissions` or `"url":"/abc/data/users/1"`
