---
tags:
  - ldap
  - enumeration
  - credential-dumping
  - privilege-escalation
  - netexec
---

# LDAP

### Low Privilege Modules

#### Enumeration

| Module            | Description                                                                                                                                                        |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `adcs`            | Find PKI Enrollment Services in Active Directory and Certificate Templates Names.                                                                                  |
| `badsuccessor`    | Check if vulnerable to bad successor attack (DMSA).                                                                                                                |
| `certipy-find`    | Certipy find command with options to export the result to text/CSV/JSON. Default: Show only vulnerable templates.                                                  |
| `daclread`        | Read and backup the Discretionary Access Control List of objects. Be careful: this module cannot read the DACLs recursively; see the options for more explanation. |
| `dns-nonsecure`   | Detects DNS zones that allow nonsecure dynamic updates.                                                                                                            |
| `dump-computers`  | Dumps FQDN and OS of all computers in the domain.                                                                                                                  |
| `entra-id`        | Find the Entra ID sync server.                                                                                                                                     |
| `enum_trusts`     | **REMOVED.** Extract all Trust Relationships, Trusting Direction, and Trust Transitivity.                                                                          |
| `find-computer`   | Finds computers in the domain via the provided text.                                                                                                               |
| `get-network`     | Query all DNS records with the corresponding IP from the domain.                                                                                                   |
| `group-mem`       | **REMOVED.** Retrieves all the members within a Group.                                                                                                             |
| `groupmembership` | Query the groups to which a user belongs.                                                                                                                          |
| `ldap-checker`    | **REMOVED.** Checks whether LDAP signing and channel binding are required and/or enforced.                                                                         |
| `maq`             | Retrieves the MachineAccountQuota domain-level attribute.                                                                                                          |
| `obsolete`        | Extract all obsolete operating systems from LDAP.                                                                                                                  |
| `pso`             | Module to get the Fine Grained Password Policy/PSOs.                                                                                                               |
| `sccm`            | Find a SCCM infrastructure in the Active Directory.                                                                                                                |
| `subnets`         | Retrieves the different Sites and Subnets of an Active Directory.                                                                                                  |
| `whoami`          | Get details of provided user.                                                                                                                                      |

#### Credential Dumping

| Module                 | Description                                                              |
| ---------------------- | ------------------------------------------------------------------------ |
| `get-desc-users`       | Get description of the users. May contain password.                      |
| `get-info-users`       | Get the info field of all users. May contain password.                   |
| `get-unixUserPassword` | Get unixUserPassword attribute from all users in LDAP.                   |
| `get-userPassword`     | Get userPassword attribute from all users in LDAP.                       |
| `laps`                 | Retrieves all LAPS passwords which the account has read permissions for. |
| `user-desc`            | Get user descriptions stored in Active Directory.                        |

#### Privilege Escalation

| Module  | Description                                                                                   |
| ------- | --------------------------------------------------------------------------------------------- |
| `pre2k` | Identify pre-created computer accounts, save the results to a file, and obtain TGTs for each. |

### High Privilege Modules

#### Privilege Escalation

| Module       | Description                                                 |
| ------------ | ----------------------------------------------------------- |
| `raisechild` | Compromise parent domain from child domain via trust abuse. |
