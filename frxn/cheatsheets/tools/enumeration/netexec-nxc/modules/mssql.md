---
tags:
  - netexec
  - mssql
  - enumeration
  - privilege-escalation
  - credential-dumping
---

# MSSQL

### Low Privilege Modules

#### Enumeration

| Module             | Description                                                  |
| ------------------ | ------------------------------------------------------------ |
| `enum_impersonate` | Enumerate users with impersonation privileges                |
| `enum_links`       | Enumerate linked SQL Servers and their login configurations. |
| `enum_logins`      | Enumerate SQL Server logins (SQL, Domain, Local users)       |

#### Privilege Escalation

| Module                 | Description                                                                          |
| ---------------------- | ------------------------------------------------------------------------------------ |
| `enable_cmdshell`      | Enable or disable xp\_cmdshell in MSSQL Server                                       |
| `exec_on_link`         | Execute commands on a SQL Server linked server                                       |
| `link_enable_cmdshell` | Enable or disable xp\_cmdshell on a linked MSSQL server                              |
| `link_xpcmd`           | Run xp\_cmdshell commands on a linked SQL server                                     |
| `mssql_coerce`         | Execute SQL commands To interact with a specified LISTENER for coercion/exfiltration |
| `mssql_priv`           | Enumerate and exploit MSSQL privileges                                               |

### High Privilege Modules

#### Enumeration

| Module            | Description  |
| ----------------- | ------------ |
| `test_connection` | Pings a host |

#### Credential Dumping

| Module     | Description                                                      |
| ---------- | ---------------------------------------------------------------- |
| `nanodump` | Get lsass dump using nanodump and parse the result with pypykatz |

#### Privilege Escalation

| Module         | Description                                                                                 |
| -------------- | ------------------------------------------------------------------------------------------- |
| `empire_exec`  | Uses Empire's RESTful API to generate a launcher for the specified listener and executes it |
| `met_inject`   | Downloads the Meterpreter stager and injects it into memory                                 |
| `web_delivery` | Kicks off a Metasploit Payload using the exploit/multi/script/web\_delivery module          |

***
