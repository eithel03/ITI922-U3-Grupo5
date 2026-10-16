# Guía práctica reproducible — ITI-922, Grupo 5

**Proyecto:** Algoritmos asimétricos y post-cuánticos  
**Práctica 1:** Chat cifrado entre dos terminales  
**Integrantes:** Eithel, Luis Diego, Rafa y Vanessa  
**Alcance de esta versión:** Comunicación TCP, intercambio X25519, HKDF, cifrado AES-256-GCM y prueba de integridad. **Pendiente para completar la práctica:** autenticación y firmas Ed25519, análisis de tráfico con Wireshark/tcpdump y pruebas de MITM (práctica 2).

## 1. Objetivo y arquitectura

Construir y comprobar un chat local cliente-servidor en Python que establezca una clave AES compartida sin enviar las claves privadas. Las dos aplicaciones se ejecutan inicialmente dentro de **una misma máquina virtual Ubuntu**, por medio de `127.0.0.1:5000`.

```text
CLIENTE                                    SERVIDOR
socket TCP -------- conexión -----------> socket TCP
X25519: clave privada + pública           X25519: clave privada + pública
         <------ claves públicas ------->
     secreto X25519                          secreto X25519
          <------ salt de servidor ---------
      HKDF(SHA-256)                         HKDF(SHA-256)
      misma clave AES-256                   misma clave AES-256
          <-- mensajes AES-GCM (nonce + texto cifrado + tag) -->
```

**Archivos de esta etapa:**

```text
ITI922-U3-Grupo5/
├── 01_chat_cifrado/
│   ├── servidor.py            # Escucha conexiones y responde mensajes
│   ├── cliente.py             # Se conecta y envía mensajes
│   ├── comunicacion.py        # Transmisión TCP con longitud prefijada
│   ├── criptografia.py        # X25519, HKDF y AES-GCM
│   ├── prueba_x25519.py       # Prueba de secretos/llaves iguales
│   └── prueba_integridad.py   # Prueba de detección de alteraciones
├── capturas/                  # Evidencias referenciadas por esta guía
├── requirements.txt
├── .gitignore
├── README.md
└── GUIA.md
```

## 2. Entorno y preparación desde Ubuntu

| Elemento | Configuración comprobada |
|---|---|
| Sistema | Ubuntu 24.04 en VirtualBox |
| Python | 3.12.3 |
| OpenSSL del sistema | 3.0.13 |
| Biblioteca Python | `cryptography` 50.0.2 |
| Comunicación | Socket TCP, `127.0.0.1`, puerto `5000` |

**Paso 1.** Actualizar el índice de paquetes e instalar herramientas:

```bash
sudo apt update
sudo apt install python3-venv python3-pip -y
```

- `sudo` ejecuta con privilegios administrativos.
- `apt update` actualiza el catálogo de paquetes disponibles; no actualiza por sí solo todos los programas.
- `apt install` instala paquetes; `python3-venv` permite entornos virtuales y `python3-pip` instala bibliotecas de Python; `-y` confirma las preguntas de instalación.

**Paso 2.** Obtener el repositorio (en una VM limpia):

```bash
cd ~
git clone https://github.com/eithel03/ITI922-U3-Grupo5.git
cd ITI922-U3-Grupo5
```

- `cd ~` cambia a la carpeta personal.
- `git clone` descarga el repositorio remoto; para repositorios privados se necesita autorización de GitHub.
- El último `cd` entra a la carpeta descargada. **Si ya clonaste el repositorio, omití `git clone`.**

**Paso 3.** Crear el entorno y preparar dependencias:

```bash
python3 -m venv env
source env/bin/activate
python -m pip install -r requirements.txt
python --version
python -m pip show cryptography
```

- `python3 -m venv env`: crea un entorno virtual aislado en `env/`.
- `source env/bin/activate`: activa ese entorno en la terminal actual; debe aparecer `(env)`.
- `python -m pip install -r requirements.txt`: instala las dependencias registradas por el equipo. Para la evidencia se empleó `cryptography==50.0.2`.
- `python --version`: muestra la versión de Python utilizada.
- `python -m pip show cryptography`: muestra versión, ubicación e información de la biblioteca.
- El directorio `env/` debe figurar en `.gitignore`: **no se sube a GitHub**.

**Evidencia 1 — entorno preparado:**

![Versiones de Python y cryptography dentro de env](capturas/01_entorno_python.png)

## 3. Prueba inicial de comunicación TCP

Esta comprobación se realizó con una primera versión **sin cifrado**, para aislar problemas de red antes de implementar criptografía. Los archivos actuales `servidor.py` y `cliente.py` corresponden a la versión **cifrada**; para repetir exactamente la etapa inicial debe consultarse el commit `ce18cee` del historial Git, sin reemplazar el código final.

En una primera terminal se ejecutó `python servidor.py`; en una segunda, `python cliente.py` (ambas desde `01_chat_cifrado/`). El servidor esperaba en `127.0.0.1:5000` y ambos intercambiaron texto de prueba.

**Explicación de las llamadas principales:** `socket()` crea la conexión TCP, `bind()` fija IP/puerto del servidor, `listen()` espera solicitudes, `accept()` acepta al cliente, `connect()` conecta desde el cliente, `sendall()` transmite datos y `recv()` recibe bytes. `close()` libera las conexiones. Esa versión inicial era solo diagnóstica; no protegía el contenido.

**Evidencia 2 — prueba inicial de sockets:**

![Cliente y servidor intercambian texto en dos terminales](capturas/02_comunicacion_sockets.png)

## 4. Intercambio X25519 y derivación HKDF

En `criptografia.py` se implementaron cuatro funciones principales:

| Función | Explicación del código |
|---|---|
| `generar_llaves()` | `X25519PrivateKey.generate()` crea una clave privada; `public_key()` obtiene la pública; `public_bytes(Encoding.Raw, PublicFormat.Raw)` la convierte en bytes para transmitirla. |
| `calcular_secreto()` | `X25519PublicKey.from_public_bytes()` reconstruye la clave pública recibida; `privada.exchange(publica_remota)` calcula el secreto compartido. |
| `generar_salt()` | `os.urandom(16)` obtiene 16 bytes aleatorios para la derivación. Este valor no es secreto y debe coincidir en ambos extremos. |
| `derivar_llave_aes()` | `HKDF(algorithm=SHA256, length=32, salt=salt, info=b"ITI922-Grupo5-Chat")` define la derivación; `.derive(secreto)` obtiene 32 bytes (256 bits). |

**Prueba independiente:** desde la raíz del repositorio, con `env` activo:

```bash
python 01_chat_cifrado/prueba_x25519.py
```

- `python` ejecuta el intérprete del entorno virtual.
- El archivo indicado genera dos pares X25519, calcula el secreto desde cada extremo, compara los secretos, deriva dos llaves AES con el mismo `salt` y comprueba longitud y coincidencia.

**Resultados esperados y observados:** `Secretos iguales: True`, `Llaves AES iguales: True` y `Tamano de la llave AES: 256 bits`.

**Evidencia 3 — X25519 y HKDF:**

![Resultado de la prueba X25519 y HKDF](capturas/03_intercambio_x25519_hkdf.png)

## 5. Integración: chat cifrado AES-GCM

**Estructura de la transmisión.** En `comunicacion.py`:

- `enviar_datos()`: `struct.pack("!I", len(datos))` crea un encabezado de 4 bytes (entero sin signo, orden de red) con la longitud; `sendall()` envía encabezado y contenido.
- `recibir_exacto()`: repite `recv()` hasta reunir la cantidad solicitada; detecta si se cierra la conexión.
- `recibir_datos()`: lee 4 bytes, recupera el tamaño con `struct.unpack("!I", encabezado)[0]`, rechaza cargas mayores de 1 MiB y recibe la carga completa.

**Criptografía de mensajes.** En `criptografia.py`:

- `cifrar_mensaje()`: genera un nonce aleatorio de 12 bytes con `os.urandom(12)`, usa `AESGCM(llave).encrypt(nonce, mensaje.encode("utf-8"), None)` y devuelve `nonce + cifrado`; el resultado de `encrypt` incluye la etiqueta de autenticación.
- `descifrar_mensaje()`: separa los primeros 12 bytes como nonce, recupera el resto como texto cifrado y etiqueta, ejecuta `AESGCM(llave).decrypt(...)` y decodifica UTF-8. Si se manipula el contenido, lanza `InvalidTag`.
- **Precaución:** no repetir un nonce con una misma llave AES-GCM. La versión de laboratorio emplea nonces aleatorios; para aplicaciones de producción se requiere un diseño y control explícitos contra reutilización.

**Flujo de servidor y cliente:** `servidor.py` escucha el puerto y `cliente.py` se conecta; ambos crean claves X25519, intercambian claves públicas, calculan el secreto y derivan la misma clave AES con el `salt` que envía el servidor. Después se envían y reciben mensajes cifrados mediante las funciones anteriores. La comunicación actual es por turnos (cliente envía y servidor responde).

**Terminal 1 — servidor** (desde cualquier directorio):

```bash
cd ~/ITI922-U3-Grupo5
source env/bin/activate
python 01_chat_cifrado/servidor.py
```

**Terminal 2 — cliente** (abrir otra terminal):

```bash
cd ~/ITI922-U3-Grupo5
source env/bin/activate
python 01_chat_cifrado/cliente.py
```

En ambos bloques:
- `cd` sitúa la terminal en la raíz del proyecto.
- `source` activa el entorno Python local.
- `python` inicia el programa indicado. **Iniciar primero el servidor** y dejar su terminal abierta.

**Resultados observados:** ambos imprimieron `Intercambio completado` y `Llave AES-256 derivada`; el cliente mostró `Comunicacion cifrada activa`; los mensajes de prueba se visualizaron correctamente tras descifrarse. La captura muestra mensajes en pantalla, **no es por sí misma evidencia del contenido de los paquetes de red**.

**Evidencia 4 — chat cifrado funcionando:**

![Chat cifrado X25519 HKDF AES-GCM en ambas terminales](capturas/04_chat_cifrado_aes_gcm.png)

## 6. Prueba de integridad AES-GCM

**Ejecutar** desde la raíz del repositorio con `env` activo:

```bash
python 01_chat_cifrado/prueba_integridad.py
```

- `python` ejecuta el script de prueba.
- El script genera una llave AES de 256 bits con `AESGCM.generate_key(bit_length=256)`.
- `cifrar_mensaje()` cifra un mensaje ficticio; `descifrar_mensaje()` confirma que se recupera intacto.
- `bytearray(cifrado)` permite modificar la salida; `manipulado[12] ^= 1` cambia un bit del primer byte cifrado **después de los 12 bytes de nonce**.
- La segunda llamada a `descifrar_mensaje()` debe producir `InvalidTag`; el bloque `except InvalidTag` confirma el rechazo.

**Resultado observado:** el mensaje `Transferir 1000 colones` se descifró correctamente antes de la alteración; después aparecieron `Manipulacion detectada correctamente` y `AES-GCM rechazo el mensaje alterado`.

**Evidencia 5 — rechazo de datos manipulados:**

![Integridad de AES-GCM: rechazo de mensaje modificado](capturas/05_integridad_aes_gcm.png)

## 7. Problemas comunes y soluciones

| Problema | Posible causa | Solución |
|---|---|---|
| `No se pudo conectar con el servidor` | No está en ejecución `servidor.py`. | Abrir terminal 1 e iniciar el servidor antes que el cliente. |
| `No such file or directory` al ejecutar Python | Se incluyó `01_chat_cifrado/` dos veces en la ruta. | Desde la raíz usar `python 01_chat_cifrado/servidor.py`; dentro de esa carpeta usar `python servidor.py`. |
| `source: env/bin/activate: No existe ...` | Se intenta activar desde `01_chat_cifrado/`. | Volver a la raíz (`cd ..`) y ejecutar `source env/bin/activate`, o utilizar `source ../env/bin/activate`. |
| `ModuleNotFoundError: cryptography` | Entorno sin activar o dependencia ausente. | Activar `env` e instalar `python -m pip install -r requirements.txt`. |
| El servidor deja de responder al cerrar su ventana | El proceso se cierra con la terminal. | Mantenerlo abierto durante la prueba; reiniciarlo si se cerró. |
| `Address already in use` | Otro proceso utiliza el puerto 5000. | Detener instancias anteriores y volver a iniciar el servidor. |
| `InvalidTag` al descifrar | Clave, nonce o datos cifrados incorrectos/manipulados. | Verificar el protocolo e investigar la alteración; no ignorar el fallo. |

## 8. Limitaciones y trabajo pendiente

1. **Autenticación pendiente:** X25519 genera un secreto compartido, pero las claves públicas recibidas no se autentican. Un intermediario podría sustituirlas. Para corregirlo, el compañero incorporará **Ed25519** y verificará firmas usando claves públicas de identidad que ya sean confiables; no basta con aceptar una clave de identidad recibida por el mismo canal sin verificar.
2. **Firmas de mensajes pendientes:** la consigna requiere mensajes cifrados con AES-GCM **y firmados con Ed25519**. La versión actual solo implementa el cifrado autenticado simétrico.
3. **Wireshark/tcpdump pendiente:** falta capturar el tráfico para verificar visualmente que el mensaje no circula en texto legible. `127.0.0.1` requiere capturar la interfaz de loopback (`lo`) o adaptar la configuración para dos VMs.
4. **Práctica 2 pendiente:** construir la demostración de MITM sin autenticación y su bloqueo con firmas confiables.
5. **Ámbito:** aplicación educativa para una conexión local y comunicación por turnos, sin endurecimiento para producción.

## 9. Registro de evidencias

| Archivo | Qué comprueba | Uso recomendado |
|---|---|---|
| `01_entorno_python.png` | Python y `cryptography` instalados | Guía práctica |
| `02_comunicacion_sockets.png` | Comunicación TCP inicial | Guía práctica |
| `03_intercambio_x25519_hkdf.png` | Secreto y llave AES coincidentes | Guía práctica |
| `04_chat_cifrado_aes_gcm.png` | Chat cifrado funcionando | Guía e informe (resultados) |
| `05_integridad_aes_gcm.png` | AES-GCM rechaza alteraciones | Guía; opcional en informe |

**Nota para el equipo:** completar esta guía después de implementar Ed25519 y registrar la captura de tráfico; actualizar instrucciones, capturas y limitaciones según los resultados **realmente verificados**.
