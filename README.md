# ITI922-U3-Grupo5

**Proyecto de algoritmos asimétricos y post-cuánticos — Seguridad de TI II**  
**Universidad Técnica Nacional | Curso ITI-922 | Unidad III: Sistemas de alta seguridad**

**Integrantes:** Eithel, Luis Diego, Rafa y Vanessa.

## Descripción

Este repositorio reúne las prácticas del Grupo 5 sobre criptografía asimétrica y post-cuántica. El objetivo es comprender cómo se establece una clave compartida, cómo se protegen los mensajes y por qué debe autenticarse el intercambio de claves para impedir ataques de intermediario (*man-in-the-middle*, MITM).

El proyecto contempla tres actividades:

1. **Chat cifrado:** comunicación TCP entre cliente y servidor mediante X25519 para el intercambio de claves, HKDF-SHA-256 para la derivación de una clave compartida y AES-256-GCM para el cifrado de mensajes. Se implementa autenticación mutua mediante Ed25519 durante el intercambio inicial, además de firmas digitales individuales para cada mensaje enviado y recibido.
2. **Demostración MITM:** un tercer programa se coloca entre el cliente y el servidor, lee y altera los mensajes del protocolo sin firmas; con firmas Ed25519 la suplantación es rechazada.
3. **Comparación clásica y post-cuántica:** medir RSA-3072, X25519 y ML-KEM-768 (tamaño de clave pública, datos enviados y tiempos de operación), y presentar tabla y gráfico.

> **Estado verificado de la Práctica 1:** chat TCP local completamente funcional mediante X25519, HKDF-SHA-256, AES-256-GCM y firmas digitales Ed25519. El sistema implementa autenticación mutua durante el intercambio de claves y firma individualmente los mensajes de ambos participantes. Se verificó el intercambio de mensajes cifrados y firmados entre cliente y servidor, así como el rechazo de mensajes modificados, firmas inválidas, identidades incorrectas y mensajes repetidos. También se comprobó la confidencialidad del tráfico mediante Wireshark.

> **Estado verificado de la Práctica 2:** ataque MITM demostrado en loopback con tres procesos (servidor, atacante y cliente). Sin firmas, el atacante descifró, leyó y alteró la conversación; con firmas Ed25519 la suplantación fue rechazada antes del primer mensaje. Incluye prueba automática, modo relay opaco y captura `pcapng` de los puertos 5000 y 5001.

> **Estado verificado de la Práctica 3:** comparación funcional de RSA-3072, X25519 y ML-KEM-768 mediante mediciones de generación de claves, operaciones criptográficas y tamaños de los datos intercambiados. Se realizaron diez mediciones por algoritmo y se generaron tablas de resultados, archivos CSV y gráficos comparativos. También se ejecutaron intercambios TCP independientes y se verificaron mediante Wireshark los tamaños de la información transmitida por cada algoritmo.

## Estructura del repositorio

```text
ITI922-U3-Grupo5/
├── 01_chat_cifrado/
│   ├── servidor.py                 # Servidor TCP autenticado y cifrado
│   ├── cliente.py                  # Cliente TCP autenticado y cifrado
│   ├── comunicacion.py             # Tramas con longitud prefijada
│   ├── criptografia.py             # X25519, HKDF, AES-GCM y Ed25519
│   ├── autenticacion.py            # Autenticación y firmas Ed25519 por mensaje
│   ├── generar_identidades.py      # Identidades locales Ed25519
│   ├── prueba_x25519.py
│   ├── prueba_integridad.py
│   ├── prueba_ed25519.py
│   └── prueba_autenticacion.py
├── 02_ataque_mitm/
│   ├── servidor_vulnerable.py      # Servidor SIN firmas (objetivo del ataque)
│   ├── cliente_vulnerable.py       # Cliente SIN firmas (conecta al atacante)
│   ├── servidor_autenticado.py     # Servidor CON firmas Ed25519
│   ├── cliente_autenticado.py      # Cliente CON firmas Ed25519
│   ├── atacante_mitm.py            # Atacante: lectura | suplantacion | relay
│   └── prueba_mitm.py              # Prueba automática del ataque y su bloqueo
├── 03_comparacion/
│   ├── comparar_algoritmos.py      # Mediciones y comparación criptográfica
│   ├── trafico_comparacion.py      # Intercambios TCP de los tres algoritmos
│   ├── resultados.csv             # Resultados de las mediciones
│   ├── resultados.md              # Tabla e interpretación de resultados
│   ├── grafico_tamanos.svg        # Gráfico comparativo de tamaños
│   └── grafico_tiempos.svg        # Gráfico comparativo de tiempos
├── capturas/                      # Evidencias de las pruebas
├── GUIA.md                        # Procedimiento y resultados detallados
├── requirements.txt
├── .gitignore
└── README.md
```

Las identidades privadas se almacenan localmente en `01_chat_cifrado/identidades/`, directorio excluido del repositorio mediante `.gitignore`. La Práctica 2 reutiliza los módulos criptográficos y las identidades Ed25519 de la Práctica 1 para demostrar el ataque MITM y su prevención. La Práctica 3 implementa la comparación de RSA-3072, X25519 y ML-KEM-768, incluyendo mediciones de rendimiento, generación de gráficos e intercambios TCP para observar el tráfico mediante Wireshark.

## Requisitos

- Ubuntu 24.04 en VirtualBox o Linux Mint 22.x (entornos verificados).
- Python 3.12.3 y `python3-venv`.
- Git para obtener y actualizar el proyecto.
- Dependencias definidas en `requirements.txt` (`cryptography` 50.0.2 en las pruebas iniciales).
- Wireshark y TShark para la captura y el análisis del tráfico TCP.

La primera etapa se ejecuta **dentro de una sola VM**, con dos terminales; no requiere configurar una segunda máquina. La dirección usada es `127.0.0.1` y el puerto TCP `5000`. La Práctica 2 usa además el puerto `5001` para el atacante.

## Instalación

Clonar el repositorio (si aún no se ha clonado):

```bash
git clone git@github.com:eithel03/ITI922-U3-Grupo5.git
cd ITI922-U3-Grupo5
```

> La URL anterior utiliza SSH: debe haberse configurado previamente una clave SSH autorizada en GitHub. Alternativamente, se puede clonar mediante HTTPS: `https://github.com/eithel03/ITI922-U3-Grupo5.git` (requiere acceso si el repositorio es privado).

Instalar herramientas de Python, crear y activar el entorno virtual:

```bash
sudo apt update
sudo apt install python3-venv python3-pip -y
python3 -m venv env
source env/bin/activate
python -m pip install -r requirements.txt
```

Para instalar las herramientas de captura de tráfico en Ubuntu:

```bash
sudo apt install wireshark tshark -y
```

Estas herramientas permiten capturar y analizar el tráfico TCP durante las prácticas.

La carpeta `env/` es local y **no se sube al repositorio**. Si se abre una terminal nueva, se debe volver a activar el entorno con `source env/bin/activate` desde la raíz del proyecto.


## Ejecución de la práctica 1: chat cifrado y autenticado

Con el entorno virtual activo, **generar las identidades una sola vez por instalación**:

```bash
python 01_chat_cifrado/generar_identidades.py
```

El programa crea las identidades Ed25519 de servidor y cliente en `01_chat_cifrado/identidades/`. Cada participante verifica las firmas usando la clave pública de identidad confiable almacenada localmente. **No regenerar las identidades entre iniciar servidor y cliente**: ambos deben utilizar el mismo conjunto de identidades configurado para la prueba.

Abrir dos terminales en la misma VM e iniciar primero el servidor.

**Terminal 1 — servidor:**

```bash
cd ~/ITI922-U3-Grupo5
source env/bin/activate
python 01_chat_cifrado/servidor.py
```

**Terminal 2 — cliente:**

```bash
cd ~/ITI922-U3-Grupo5
source env/bin/activate
python 01_chat_cifrado/cliente.py
```

El servidor y el cliente generan e intercambian claves públicas efímeras X25519. El intercambio y sus parámetros se autentican mediante firmas digitales Ed25519, permitiendo verificar las identidades de ambos participantes.

Una vez completada la autenticación mutua, ambos calculan el mismo secreto compartido y derivan una clave AES de 256 bits mediante HKDF-SHA-256.

Durante la comunicación, cada mensaje se firma individualmente con la clave privada Ed25519 del emisor. La firma se vincula al contenido del mensaje, a la identidad del remitente, a los parámetros del intercambio de claves y a un número de secuencia.

Posteriormente, el mensaje y su firma se cifran utilizando AES-256-GCM y se transmiten mediante TCP.

Al recibir los datos, el destinatario los descifra y verifica la firma digital utilizando la clave pública Ed25519 correspondiente. Si la firma no es válida, el mensaje fue modificado o el número de secuencia es incorrecto, la comunicación rechaza el mensaje.

La aplicación funciona por turnos: primero escribe el cliente y después responde el servidor. Para finalizar la comunicación, se utiliza el comando `salir`.

**Salida verificada en el cliente:**

```text
[ED25519] Servidor autenticado correctamente.
[ED25519] Firma del cliente enviada.
[X25519] Intercambio autenticado.
[HKDF] Llave AES-256 derivada.
[ED25519] Autenticacion mutua completada.
[AES-GCM] Comunicacion cifrada activa.
```

## Pruebas realizadas y resultados

Ejecutar desde la raíz del repositorio, con `env` activo:

```bash
python 01_chat_cifrado/prueba_x25519.py
python 01_chat_cifrado/prueba_integridad.py
python 01_chat_cifrado/prueba_ed25519.py
python 01_chat_cifrado/prueba_autenticacion.py
```

| Prueba | Resultado observado |
|---|---|
| X25519 + HKDF | Secretos iguales `True`, claves AES iguales `True`, longitud 256 bits. |
| Integridad AES-GCM | El mensaje original se recupera; una alteración provoca rechazo (`InvalidTag`). |
| Firmas Ed25519 | Firma legítima `True`; mensaje modificado `False`; firma incorrecta `False`. |
| Autenticación del intercambio | Firma legítima `True`; identidad falsa `False`; clave X25519 modificada `False`; `salt` modificado `False`. |
| Chat autenticado | Cliente y servidor intercambiaron mensajes y confirmaron autenticación mutua. |
| Wireshark | Captura en `lo`, TCP puerto 5000, de una carga de 53 bytes para el mensaje de prueba de 21 bytes. |
| Firmas individuales Ed25519 | Cada mensaje enviado por el cliente y el servidor fue firmado digitalmente y verificado correctamente por el receptor. |
| Modificación de mensajes firmados | Un mensaje cuyo contenido fue alterado sin generar una nueva firma fue rechazado. |
| Protección contra repetición | Un mensaje con un número de secuencia diferente al esperado fue rechazado. |
| Verificación de identidad | Una firma generada con la identidad del cliente no fue aceptada como firma del servidor. |
| Comunicación completa | Cliente y servidor intercambiaron tres mensajes consecutivos con cifrado AES-256-GCM y firmas Ed25519 válidas. |

Las pruebas funcionales confirmaron que el sistema genera y verifica correctamente firmas Ed25519 individuales para los mensajes intercambiados. Se comprobó que los mensajes legítimos son aceptados y que las alteraciones del contenido, las identidades incorrectas y los números de secuencia inesperados provocan el rechazo de la verificación.

Adicionalmente, se ejecutó una comunicación entre cliente y servidor en la que se intercambiaron tres mensajes consecutivos. En todos los casos, ambos participantes verificaron correctamente las firmas recibidas y mantuvieron la comunicación cifrada mediante AES-256-GCM.

### Evidencia de tráfico cifrado

Wireshark 4.2.2 se utilizó sobre la interfaz de loopback `lo` con el filtro de visualización:

```text
tcp.port == 5000 && tcp.len > 0
```

Para identificar el envío del mensaje ASCII `PRUEBA_AES_256_GRUPO5` se empleó:

```text
tcp.port == 5000 && tcp.len == 53
```

El mensaje tiene 21 bytes. La trama de aplicación observada contiene **4 bytes de longitud + 12 bytes de nonce + 21 bytes de texto cifrado + 16 bytes de etiqueta GCM = 53 bytes**. En Wireshark se identificó el paquete 50 con `Data (53 bytes)` y contenido hexadecimal, sin el texto original en claro. El tamaño y la captura son consistentes con el formato implementado; la garantía criptográfica se sustenta además en el código y las pruebas de integridad.

**Nota sobre la captura:** esta evidencia corresponde a las pruebas iniciales de AES-256-GCM, antes de incorporar las firmas digitales individuales. En la versión actual, cada mensaje incluye un sobre JSON con su contenido, firma Ed25519, versión del formato y número de secuencia. Este sobre se cifra mediante AES-256-GCM, por lo que el tamaño de los datos transmitidos es mayor que el observado en la captura original.

La implementación actual de firmas individuales se verificó mediante pruebas de validación de firmas y mediante el intercambio de mensajes entre cliente y servidor.

![Datos cifrados observados en Wireshark](capturas/10_datos_cifrados_aes_gcm.png)

El registro completo se encuentra en [`capturas/chat_cifrado_grupo5.pcapng`](capturas/chat_cifrado_grupo5.pcapng). Para el procedimiento detallado y todas las imágenes, consultar **[GUIA.md](GUIA.md)**.

## Alcance y limitaciones de la Práctica 1

La implementación integra X25519, HKDF-SHA-256, AES-256-GCM y Ed25519 para establecer una comunicación cifrada y autenticada entre cliente y servidor.

Ed25519 permite autenticar el intercambio inicial de claves y verificar individualmente los mensajes transmitidos durante la comunicación. Cada mensaje incorpora una firma digital asociada al contenido, la identidad del emisor, los parámetros de la sesión y un número de secuencia.

Las pruebas realizadas confirmaron el funcionamiento de las firmas individuales, la comunicación cifrada y el rechazo de mensajes modificados, firmas inválidas, identidades incorrectas y mensajes repetidos.

La demostración funciona en un entorno local controlado mediante 127.0.0.1:5000, con una conexión TCP y comunicación por turnos.


## Ejecución de la práctica 2: demostración del ataque MITM

La Práctica 2 reutiliza los módulos criptográficos y las identidades de la Práctica 1. Con el entorno activo, ejecutar primero la prueba automática:

```bash
python 02_ataque_mitm/prueba_mitm.py
```

Para la demostración en vivo se usan **tres terminales** (servidor, atacante y cliente), en ese orden de inicio:

**Escenario A — ataque exitoso sin firmas:**

```bash
python 02_ataque_mitm/servidor_vulnerable.py   # terminal 1
python 02_ataque_mitm/atacante_mitm.py         # terminal 2 (modo lectura)
python 02_ataque_mitm/cliente_vulnerable.py    # terminal 3
```

El atacante descifra, imprime y reenvía (alterado) cada mensaje entre el cliente y el servidor.

**Escenario B — suplantación bloqueada con firmas:**

```bash
python 02_ataque_mitm/servidor_autenticado.py       # terminal 1
python 02_ataque_mitm/atacante_mitm.py suplantacion # terminal 2
python 02_ataque_mitm/cliente_autenticado.py        # terminal 3
```

El cliente muestra `[SEGURIDAD] Firma del servidor invalida` y cierra antes del primer mensaje.

**Escenario C — relay opaco con firmas:**

```bash
python 02_ataque_mitm/servidor_autenticado.py  # terminal 1
python 02_ataque_mitm/atacante_mitm.py relay   # terminal 2
python 02_ataque_mitm/cliente_autenticado.py   # terminal 3
```

La sesión autenticada funciona a través del atacante, que solo observa bytes cifrados. El procedimiento completo y las salidas se documentan en [GUIA.md](GUIA.md); el registro de paquetes del Escenario A está en [`capturas/ataque_mitm_grupo5.pcapng`](capturas/ataque_mitm_grupo5.pcapng).


## Ejecución de la práctica 3: comparación clásica y post-cuántica

La tercera práctica consiste en comparar tres mecanismos criptográficos: **RSA-3072**, **X25519** y **ML-KEM-768**.

El objetivo es observar sus diferencias en cuanto al tamaño de las claves públicas, la cantidad de datos transmitidos durante el establecimiento de un secreto compartido y los tiempos necesarios para ejecutar las operaciones criptográficas.

### Algoritmos utilizados

- **RSA-3072:** algoritmo asimétrico clásico basado en la dificultad de factorizar números enteros grandes. En esta práctica se utiliza RSA-OAEP para cifrar y recuperar un secreto de 32 bytes.
- **X25519:** mecanismo de intercambio de claves basado en curvas elípticas. Permite que dos participantes calculen un secreto compartido a partir de sus claves privadas y las claves públicas recibidas.
- **ML-KEM-768:** mecanismo post-cuántico de encapsulación de claves estandarizado por NIST mediante FIPS 203. Permite establecer un secreto compartido utilizando un proceso de encapsulación y desencapsulación, con el objetivo de ofrecer resistencia frente a ataques cuánticos conocidos.

---

### 1. Ejecutar la comparación de algoritmos

Desde la raíz del repositorio, activar el entorno virtual:

```bash
source env/bin/activate
```

Ejecutar el programa de comparación:

```bash
python 03_comparacion/comparar_algoritmos.py
```

El programa realiza diez mediciones por algoritmo y calcula los valores promedio de generación de claves y operaciones criptográficas.

Al finalizar, genera cuatro archivos en `03_comparacion/`:

- `resultados.csv`: resultados de las mediciones en formato CSV.
- `resultados.md`: tabla comparativa e interpretación de los datos.
- `grafico_tamanos.svg`: gráfico de los tamaños de los intercambios.
- `grafico_tiempos.svg`: gráfico comparativo de tiempos de operación.

> **Nota:** Al ejecutar el programa desde su ubicación original, los archivos de resultados existentes se actualizan con las nuevas mediciones. Los tiempos pueden variar según el equipo y la carga del sistema.

---

### 2. Resultados de la comparación

Los tamaños utilizados para comparar los intercambios criptográficos son los siguientes:

| Algoritmo | Tamaño de clave pública | Datos del intercambio |
| --- | --- | --- |
| **RSA-3072** | 422 bytes | 806 bytes |
| **X25519** | 32 bytes | 64 bytes |
| **ML-KEM-768** | 1184 bytes | 2272 bytes |

- En **RSA-3072** se contabiliza la clave pública codificada en formato DER/SPKI y el texto cifrado generado mediante RSA-OAEP.
- En **X25519** se consideran las dos claves públicas de 32 bytes intercambiadas por los participantes.
- En **ML-KEM-768** se contabiliza la clave pública de 1184 bytes y el texto cifrado de encapsulación de 1088 bytes.

Estas cantidades corresponden únicamente a los datos criptográficos modelados, sin incluir cabeceras TCP/IP u otros elementos de transporte.

---

### 3. Medición de tiempos

El programa utiliza diez ejecuciones de cada algoritmo para calcular los tiempos promedio de generación de claves y operación principal.

Los resultados permiten comparar el comportamiento de los tres mecanismos bajo las mismas condiciones de ejecución.

Las operaciones medidas no son idénticas: RSA realiza cifrado y descifrado de un secreto, X25519 calcula un secreto compartido y ML-KEM encapsula y desencapsula un secreto.

Por esta razón, la interpretación debe considerar tanto los tiempos obtenidos como las diferencias funcionales de cada algoritmo.

---

### 4. Ejecutar los intercambios TCP

Para observar los datos transmitidos por la red, ejecutar:

```bash
python 03_comparacion/trafico_comparacion.py
```

El programa realiza tres intercambios mediante conexiones TCP locales, utilizando los siguientes puertos:

| Algoritmo | Puerto TCP |
| --- | --- |
| **RSA-3072** | 5101 |
| **X25519** | 5102 |
| **ML-KEM-768** | 5103 |

La ejecución correcta muestra:

```text
RSA-3072: intercambio TCP completado en puerto 5101
X25519: intercambio TCP completado en puerto 5102
ML-KEM-768: intercambio TCP completado en puerto 5103
Los tres intercambios terminaron correctamente.
```

---

### 5. Captura del tráfico mediante TShark

Para capturar los intercambios, abrir dos terminales.

**Terminal 1 — iniciar captura:**

```bash
sudo tshark -i lo -f "tcp portrange 5101-5103" -w /tmp/comparacion_grupo5.pcapng
```

Este comando captura el tráfico TCP de los puertos utilizados por los tres algoritmos mediante la interfaz de loopback `lo`.

**Terminal 2 — ejecutar los intercambios:**

```bash
python 03_comparacion/trafico_comparacion.py
```

Cuando finalice la ejecución, regresar a la primera terminal y detener la captura mediante `Ctrl + C`.

Si el archivo de captura quedó propiedad de `root`, se pueden ajustar sus permisos:

```bash
sudo chown "$USER":"$USER" /tmp/comparacion_grupo5.pcapng
```

Posteriormente, abrir el archivo:

```bash
wireshark /tmp/comparacion_grupo5.pcapng
```

---

### 6. Análisis en Wireshark

Para visualizar únicamente los paquetes TCP que contienen datos, aplicar los siguientes filtros:

- **RSA-3072:**
  `tcp.port == 5101 && tcp.len > 0`
- **X25519:**
  `tcp.port == 5102 && tcp.len > 0`
- **ML-KEM-768:**
  `tcp.port == 5103 && tcp.len > 0`

Las capturas permitieron verificar las siguientes longitudes de datos:

| Algoritmo | Primer mensaje | Segundo mensaje |
| --- | --- | --- |
| **RSA-3072** | 422 bytes | 384 bytes |
| **X25519** | 32 bytes | 32 bytes |
| **ML-KEM-768** | 1184 bytes | 1088 bytes |

Los tamaños observados en Wireshark coincidieron con las cantidades calculadas por los programas de comparación.

---

### 7. Interpretación de los resultados

Los resultados permiten identificar diferencias relevantes entre los tres mecanismos criptográficos.

- **RSA-3072** presenta claves públicas considerablemente mayores que X25519 y requiere operaciones relacionadas con la aritmética de números enteros grandes.
- **X25519** utiliza claves públicas de 32 bytes y presenta el menor tamaño de intercambio entre los mecanismos evaluados.
- **ML-KEM-768** requiere transmitir una mayor cantidad de datos, pero proporciona un mecanismo de establecimiento de secretos diseñado para resistir ataques de computadoras cuánticas suficientemente potentes.

La comparación demuestra que la selección de un mecanismo criptográfico debe considerar tanto sus propiedades de seguridad como sus requerimientos de rendimiento y comunicación.

La utilización de ML-KEM representa una alternativa post-cuántica para el establecimiento de secretos compartidos, mientras que RSA y X25519 corresponden a mecanismos clásicos que deben evaluarse considerando la evolución de las capacidades de cómputo cuántico.

---

### 8. Evidencias

Los resultados de la práctica se encuentran organizados en el directorio `03_comparacion/`.

Se incluyen archivos CSV, tablas de resultados, gráficos comparativos y programas para generar tráfico TCP.

Las capturas de Wireshark se encuentran en el directorio `capturas/`, donde se documenta el intercambio de información asociado a cada algoritmo.

## Seguridad y colaboración

- Usar solamente mensajes y datos de prueba. No introducir información personal o confidencial.
- No subir claves privadas, credenciales, tokens ni el entorno virtual `env/`.
- Cada integrante debe registrar sus propios cambios mediante commits en su rama y presentar un *Pull Request* para integrarlos en `main`.
- Las pruebas del ataque MITM deben ejecutarse exclusivamente en el entorno controlado del grupo.

## Documentación

Consultar [GUIA.md](GUIA.md) para el procedimiento detallado de instalación, explicación de comandos, ejecución y evidencias de las pruebas realizadas.
