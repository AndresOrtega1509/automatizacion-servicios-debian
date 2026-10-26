# Consola de Automatización Debian

Aplicación web desarrollada en **Go** para automatizar tareas de administración sobre máquinas virtuales **Debian GNU/Linux 13.7** ejecutadas en Oracle VirtualBox.

La solución funciona como una consola de administración remota desde el navegador. Permite solicitar operaciones sobre el sistema, validar los datos ingresados, ejecutar acciones en las máquinas virtuales y mostrar tanto un mensaje comprensible para el usuario como información técnica para verificar el resultado o diagnosticar errores.

El proyecto fue desarrollado para automatizar tareas que normalmente se realizan manualmente desde la terminal, entre ellas la instalación de paquetes, configuración de SSH, gestión de usuarios, administración de servicios con `systemd` y configuración de servidores backend en HAProxy.

---

## Tecnologías utilizadas

- **Go 1.27.1**
- **Debian GNU/Linux 13.7**
- **Oracle VirtualBox 7.0.22**
- **VirtualBox Guest Additions**
- **OpenSSH / SCP**
- **systemd**
- **HAProxy 3.0.11**
- **HTML / CSS**

---

## Arquitectura general

La aplicación se ejecuta en el equipo host con Windows y administra las máquinas virtuales de forma remota.

Durante la etapa inicial se utiliza **VirtualBox Guest Additions** mediante `VBoxManage` para realizar operaciones dentro de la máquina virtual.

Después de configurar las llaves SSH, las operaciones administrativas se realizan mediante **SSH con autenticación por llaves ED25519**.

El flujo general de la solución es:

```text
Formulario web
      ↓
Validación de entradas
      ↓
Ejecución remota
      ↓
Verificación del resultado
      ↓
Resultado amigable + detalle técnico
```

Máquinas utilizadas:

```text
Host Windows
   │
   ├── NP2-Pruebas
   │     Debian GNU/Linux 13.7
   │     IP: 192.168.1.45
   │
   └── NP2-HAProxy
         Debian GNU/Linux 13.7
         IP: 192.168.1.46
         HAProxy 3.0.11
```

---

# Funcionalidades

## 1. Preparación del sistema

### Instalación y eliminación de paquetes

Desde la interfaz web se puede ingresar el nombre de un paquete Debian y solicitar su instalación o eliminación.

La aplicación:

- valida el nombre del paquete;
- ejecuta la operación dentro de la máquina virtual;
- verifica el estado final;
- muestra un resultado comprensible;
- presenta la salida técnica para diagnóstico.

Ejemplo utilizado durante las pruebas:

```bash
dpkg -s tree
```

Desde la interfaz se puede instalar o eliminar el paquete `tree` y posteriormente comprobar su estado en Debian.

---

### Configuración SSH de root

La aplicación permite preparar el acceso remoto seguro mediante un par de llaves **ED25519**.

El proceso incluye:

- generación del par de llaves;
- instalación de la llave pública en:

```text
/root/.ssh/authorized_keys
```

- creación de configuración específica para SSH;
- habilitación de autenticación mediante llave pública;
- deshabilitación del acceso de `root` mediante contraseña;
- validación de la configuración con `sshd -t`;
- recarga del servicio SSH;
- descarga de la llave privada desde la aplicación.

Ejemplo de conexión:

```powershell
ssh -i "RUTA\np2-root-ed25519" -o IdentitiesOnly=yes root@192.168.1.45
```

---

### Personalización de `/etc/issue`

Desde la aplicación se puede configurar el mensaje mostrado antes del inicio de sesión en Debian.

Opciones disponibles:

- hostname;
- fecha;
- hora;
- dirección IPv4;
- mensaje personalizado.

La modificación se realiza remotamente mediante SSH.

Ejemplo de contenido:

```text
Debian GNU/Linux 13 \l
Hostname: \n
Fecha: \d
Hora: \t
IP Address: \4
Mensaje: Bienvenido al servidor NP2
```

---

### Configuración del hostname y `/etc/hosts`

La aplicación permite modificar el nombre del sistema de forma remota.

Se realiza:

```bash
hostnamectl set-hostname
```

y posteriormente se actualiza la entrada correspondiente en:

```text
/etc/hosts
```

La aplicación valida el nombre ingresado y verifica que el cambio haya sido aplicado correctamente.

---

# 2. Gestión de usuarios

La aplicación permite crear y eliminar usuarios del sistema desde la interfaz web.

## Crear usuario

Opciones disponibles:

- nombre de usuario;
- contraseña inicial;
- asignación al grupo `sudo`;
- generación de un par de llaves SSH.

Cuando se habilita el acceso mediante SSH:

- se genera una llave ED25519;
- la llave pública se instala en `authorized_keys`;
- se configura el acceso mediante llave;
- se deshabilita la autenticación por contraseña para el usuario;
- la llave privada puede descargarse desde la interfaz.

La aplicación también permite verificar los grupos asignados al nuevo usuario.

---

## Eliminar usuario

Los usuarios disponibles se consultan directamente desde Debian mediante SSH y se muestran en un **menú desplegable**.

Esto evita tener que escribir manualmente el nombre del usuario y reduce errores de digitación.

La aplicación:

- consulta `/etc/passwd`;
- muestra usuarios normales con UID igual o superior a 1000;
- excluye usuarios protegidos como `root`, `andres` y `nobody`;
- permite seleccionar el usuario desde un desplegable;
- permite elegir si se desea eliminar también su directorio personal y archivos.

Opciones disponibles:

```text
Eliminar usuario
Eliminar usuario + archivos
```

---

# 3. Gestión de servicios con systemd

La aplicación permite preparar y controlar servicios administrados mediante `systemd`.

Para las pruebas se utiliza un script que registra la fecha y hora de cada ejecución en:

```text
/var/log/np2-fecha.log
```

La aplicación crea:

```text
/usr/local/bin/np2-fecha.sh
```

y:

```text
/etc/systemd/system/np2-fecha.service
```

Posteriormente ejecuta:

```bash
systemctl daemon-reload
```

Desde la interfaz se encuentran disponibles las siguientes operaciones:

- **Start**
- **Stop**
- **Restart**
- **Status**
- **Enable**
- **Disable**

El servicio de prueba utiliza:

```ini
Type=oneshot
RemainAfterExit=yes
```

De esta forma se puede comprobar fácilmente cuándo fue ejecutado el script.

Ejemplo de log:

```text
2026-10-26 15:06:19 - Servicio NP2 ejecutado correctamente
2026-10-26 15:10:04 - Servicio NP2 ejecutado correctamente
```

---

# 4. Gestión de HAProxy

La aplicación permite administrar servidores dentro de un backend de HAProxy mediante SSH.

Operaciones disponibles:

- agregar servidor;
- consultar backend;
- eliminar servidor.

Ejemplo de configuración generada:

```haproxy
backend np2_backend
    balance roundrobin
    server backend01 192.168.1.50:8080 check
```

Antes de aplicar cualquier cambio se valida la configuración mediante:

```bash
haproxy -c -f /etc/haproxy/haproxy.cfg
```

Además:

- se crea una copia de seguridad antes de modificar el archivo;
- si la configuración resultante es inválida, se restaura automáticamente la copia;
- HAProxy únicamente se recarga cuando la validación es correcta.

---

# Validaciones y manejo de errores

La aplicación incorpora validaciones para reducir errores durante la administración remota.

Entre ellas se encuentran:

- validación del nombre de paquetes;
- validación de nombres de usuario;
- validación del hostname;
- validación de direcciones IPv4;
- validación de puertos;
- validación de nombres de servicios;
- validación de nombres de backend;
- comprobación del estado final después de cada operación.

Cada operación muestra:

```text
Resultado para el usuario
+
Detalle técnico
```

Esto facilita comprobar si la automatización fue ejecutada correctamente.

---

# Ejecución

## Requisitos

Antes de ejecutar la aplicación se requiere:

- Go instalado en Windows;
- Oracle VirtualBox;
- máquina virtual Debian disponible;
- OpenSSH disponible;
- llave privada de administración configurada;
- máquinas virtuales encendidas y accesibles por red.

---

## Iniciar la aplicación

Desde PowerShell:

```powershell
cd "RUTA\consola-automatizacion-debian"
go run .
```

Posteriormente abrir en el navegador:

```text
http://127.0.0.1:8080
```

---

# Estructura principal

```text
consola-automatizacion-debian/
│
├── main.go
├── go.mod
├── README.md
│
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── preparacion.html
│   ├── usuarios.html
│   ├── servicios.html
│   └── haproxy.html
│
└── static/
    └── styles.css
```

---

# Consideraciones de seguridad

Las operaciones administrativas requieren privilegios elevados, por lo que se implementaron algunas medidas de seguridad:

- autenticación SSH mediante llaves ED25519;
- deshabilitación de contraseña para usuarios configurados con llave;
- validación de entradas antes de ejecutar comandos;
- protección contra eliminación de usuarios administrativos;
- uso temporal de credenciales durante la configuración inicial;
- copia de seguridad de la configuración de HAProxy antes de modificarla;
- validación de HAProxy antes de recargar el servicio.

La llave privada SSH debe mantenerse protegida y no debe publicarse dentro del repositorio.

Se recomienda agregar al archivo `.gitignore` cualquier llave privada:

```gitignore
*.pem
*.key
np2-root-ed25519
np2-*-ed25519
```

---

# Pruebas realizadas

Durante el desarrollo se verificaron, entre otros, los siguientes escenarios:

- instalación de un paquete inexistente inicialmente;
- comprobación del paquete instalado;
- eliminación del paquete;
- autenticación SSH mediante llave;
- modificación de `/etc/issue`;
- cambio de hostname;
- creación de usuarios;
- asignación de privilegios `sudo`;
- acceso SSH de usuarios mediante llave;
- eliminación de usuario y archivos;
- ejecución de acciones `systemd`;
- registro de fecha y hora del servicio;
- alta de servidor en HAProxy;
- consulta del backend;
- eliminación del servidor del backend.

---

# Problemas encontrados durante el desarrollo

Durante las primeras pruebas de eliminación de paquetes, Debian realizaba correctamente la operación, pero la aplicación interpretaba como error el código de salida de una comprobación posterior.

La solución consistió en incorporar una validación explícita del estado final del paquete, permitiendo diferenciar entre:

- ejecución correcta de `apt`;
- comprobación posterior mediante `dpkg-query`.

De esta forma, una eliminación correcta ya no se presenta como fallo.