---
title: Cómo crear una contraseña segura con Python
author: HackerCloud
date: 2022-08-31 00:00:00 +0800
categories: [Python, Password]
tags: [Password, security]
image:
  path: ../../assets/img/commons/python-password/python-password.png
  width: 800
  height: 500
  alt: Python Password
---

# Cómo crear una contraseña segura con python

#### ¿Qué es python?

Python es un lenguaje de programación usado para aplicaciones de todo tipo, entre ellas se encuentran: aplicaciones web, aplicaciones de escritorio y gráficas, aplicaciones de terminal. Se usa mucho para automatizar acciones es un lenguaje de programación multiparadigma, ya que soporta parcialmente la programación orientada a objetos.

#### ¿Qué tiene que tener una contraseña segura? 

Para que tu contraseña sea segura tiene que tener más de 15 caracteres, entre ellos debe haber:  

-   Caracteres especiales (#$%&)
-   Números (254)
-   Letras (abc)
-   Mayúsculas y minúsculas

También es importante:

-   Que no sea una palabra
-   Que no esté relaccionada contigo
-   Que no se repita en otras cuentas

#### **Cómo hacer una contraseña segura con Python**

Este es un ejemplo de como hacer una contraseña segura con Python:

```python
import base64
from random import choice


chars = 'qwertyuiopasdfghjklzzxcvbnmdfg'
nums = '1230983655645987'
chars_uppercase = chars.upper()
specials = '!$%&'

all = chars_uppercase+nums+chars+specials

pass_gen = ''.join(
    choice(all) for i in range(60)
)

encoded_pass = (base64.b64encode(pass_gen.encode('ascii')))
encoded_ascii = encoded_pass.decode('ascii')

print(encoded_ascii)
```

#### Explicación del código

Empezamos importando las librerías, para este proyecto solo se necesita el módulo choice de la librería random y la librería base64.  
  
Después creamos las variables principales que vamos a usar, en este caso son: chars (caracteres), nums (números), specials (caracteres especiales), es importante que los caracteres sean aleatorios para una mayor seguridad.  
  
Lo siguiente es crear una variable que mezcle todas las variables anteriores, para crear una sola.  
  
Después creamos la variable password y meteremos el código para crear la contraseña de forma aleatoria, en mi código puse 50 porque quiero 50 dígitos en mi contraseña, esto se puede cambiar.  
  
Lo siguiente es encriptar la contraseña, yo usé base64 pero la librería base64 incluye base16, base58, base32..., por último imprimimos la contraseña por consola para ver el resultado final.

Lo de convertirlo a base64 es opcional, esto evade completamente los simbolos especiales, si quieres los simbolos simplemente usa este código:

```python
from random import choice


chars = 'qwertyuiopasdfghjklzzxcvbnmdfg'
nums = '1230983655645987'
chars_uppercase = chars.upper()
specials = '!$%&'

all = chars_uppercase+nums+chars+specials

final_pass = ''.join(
    choice(all) for i in range(60)
)

print(final_pass)
```
