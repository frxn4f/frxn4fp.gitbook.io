# (139-445) SMB

Credenciales — añade la flag según contexto

| Herramienta     | Anónimo / null | Guest              | Auth            |
| --------------- | -------------- | ------------------ | --------------- |
| `nxc`           | _(sin flags)_  | `-u 'guest' -p ''` | `-u 'u' -p 'p'` |
| `smbmap`        | _(sin flags)_  | `-u 'guest' -p ''` | `-u 'u' -p 'p'` |
| `smbclient`     | `-N`           | `-U 'guest%'`      | `-U 'u%p'`      |
| `enum4linux-ng` | —              | —                  | `-u 'u' -p 'p'` |

Los comandos de abajo se muestran en su forma **anónima/guest** (la más usada en OSCP). Añade la flag de la tabla para probar con credenciales reales.

***

### 0 - Fingerprint

```bash
> nmap -sV -sC -p139,445 $IP                     # versión SMB + scripts básicos
> nmap -p445 --script smb-os-discovery $IP       # SO, dominio, NetBIOS
> nmap -p445 --script smb-security-mode $IP      # signing / nivel auth
> nmap -p445 --script smb2-security-mode $IP     # signing SMB2/3 (relay)
> nmap -p445 --script smb-vuln-ms17-010 $IP      # check EternalBlue
> nbtscan -r $IP                                 # nombre NetBIOS + MAC
> nxc smb $IP                                    # banner + signing:True/False
```

***

### 1 - Sesión

```bash
> smbclient -N -L //$IP                          # listar shares, null session
> smbclient -L //$IP -U 'guest%'                 # listar shares como guest
```

***

### 2 - Shares

```bash
> smbmap -H $IP                                  # listado + permisos por share
> smbmap -H $IP -r '<share>'                     # contenido de un share
> smbmap -H $IP -R '<share>' -q -A '.*'          # descarga recursiva completa
> nxc smb $IP --shares                           # READ/WRITE (rápido)
> smbclient //$IP/<share> -N                     # conectar al share
# dentro: recurse ON · prompt OFF · mget *
> sudo mount -t cifs -o 'username=u,password=p' //$IP/<share> /mnt/s
                                               # montar para explorar con ls/find
```

> READ en SMB ≠ sin WRITE en NTFS → confirma subiendo un fichero.

***

### 3 - Usuarios / Grupos

```bash
> nxc smb $IP --users                          # lista usuarios (SAMR)
> nxc smb $IP --groups                         # lista grupos
> nxc smb $IP --rid-brute                      # fuerza RIDs → usuarios+grupos
> enum4linux-ng -A $IP                         # "todo en uno" (users/shares/pol)
```

***

### 4 - Checks de seguridad

```bash
> nxc smb $IP --pass-pol                         # política de contraseñas
> nxc smb $IP --gen-relay-list relay.txt         # hosts sin signing → relay
> enum4linux-ng -P $IP                           # política vía RPC
> nxc smb $IP -M ms17-010                        # check EternalBlue
```

***

### 5 - Extracción

```bash
# DC → SYSVOL / NETLOGON legibles por cualquier usuario auth
> smbclient //$IP/SYSVOL -U 'u%p'               # buscar Groups.xml / Registry.xml
> smbclient //$IP/NETLOGON -U 'u%p'             # scripts logon, *.config
# cpassword en Groups.xml → gpp-decrypt <hash>
```

***

### Extra

**Módulos de NetExec**: [smb.md](../tools/enumeration/netexec-nxc/modules/smb.md "mention")

### Checklist

* [ ] `signing:False` → relay
* [ ] null / guest activo
* [ ] shares RW confirmados
* [ ] usuarios + RIDs extraídos
* [ ] SYSVOL/NETLOGON revisado (si DC)
* [ ] MS17-010 (solo check)
