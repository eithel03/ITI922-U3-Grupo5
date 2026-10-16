# ITI922-U3-Grupo5

**Proyecto de algoritmos asimétricos y post-cuánticos — Seguridad de TI II**  
**Universidad Técnica Nacional | Curso ITI-922 | Unidad III: Sistemas de alta seguridad**

**Integrantes:** Eithel, LuisDiego, Rafa y Vanessa.

## Descripción

Este repositorio reúne las prácticas del Grupo 5 sobre criptografía asimétrica y post-cuántica. El objetivo es comprender cómo se establece una clave compartida, cómo se protegen los mensajes y por qué debe autenticarse el intercambio de claves para impedir ataques de intermediario (*man-in-the-middle*, MITM).

El proyecto contempla tres actividades:

1. **Chat cifrado:** comunicación TCP entre cliente y servidor con X25519, HKDF, AES-256-GCM y, como siguiente fase, firmas Ed25519.
2. **Demostración MITM:** mostrar el riesgo del intercambio no autenticado y cómo impedir la suplantación mediante autenticación de claves.
3. **Comparación clásica y post-cuántica:** medir RSA-3072, X25519 y ML-KEM-768 (tamaño de clave pública, datos enviados y tiempos de operación), y presentar tabla y gráfico.

> **Estado actual:** está implementada y probada una versión local del chat con sockets TCP, intercambio X25519, derivación HKDF y cifrado autenticado AES-GCM. **Todavía no incorpora Ed25519 ni autenticación de identidad**; por tanto, el intercambio de claves puede ser vulnerable a MITM. No utilizar esta versión para comunicaciones reales o datos sensibles.

## Estructura del repositorio

```text
ITI922-U3-Grupo5/
├── 01_chat_cifrado/
│   ├── servidor.py           # Servidor TCP y chat cifrado
│   ├── cliente.py            # Cliente TCP y chat cifrado
│   ├── criptografia.py       # X25519, HKDF y AES-GCM
│   ├── comunicacion.py       # Envío/recepción con longitud de mensaje
│   ├── prueba_x25519.py      # Prueba de secreto y clave derivados
│   └── prueba_integridad.py  # Prueba de detección de manipulación AES-GCM
├── 02_ataque_mitm/           # Pendiente de implementar
├── 03_comparacion/           # Pendiente de implementar
├── capturas/                # Evidencias para la guía, si se incluyen
├── GUIA.md                  # Procedimiento reproducible y evidencias
├── requirements.txt         # Dependencias de Python
├── .gitignore
└── README.md
```

La estructura se irá ampliando a medida que el grupo integre el resto de las prácticas.

## Requisitos

- Ubuntu 24.04 en VirtualBox (entorno de desarrollo probado).
- Python 3.12.3 y `python3-venv`.
- Git para obtener y actualizar el proyecto.
- Dependencias definidas en `requirements.txt` (`cryptography` 50.0.2 en las pruebas iniciales).

La primera etapa se ejecuta **dentro de una sola VM**, con dos terminales; no requiere configurar una segunda máquina. La dirección usada es `127.0.0.1` y el puerto TCP `5000`.

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

La carpeta `env/` es local y **no se sube al repositorio**. Si se abre una terminal nueva, se debe volver a activar el entorno con `source env/bin/activate` desde la raíz del proyecto.

## Ejecución de la práctica 1: chat cifrado

Abrir **dos terminales en la misma VM**. Iniciar siempre el servidor antes que el cliente.

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

El cliente y el servidor intercambian claves públicas X25519, obtienen el mismo secreto compartido y derivan una clave AES de 256 bits con HKDF. A partir de ese momento los mensajes se envían cifrados con AES-GCM. Los mensajes aparecen **descifrados en las terminales** de los participantes. Para finalizar, escribir `salir`.

> Esta versión funciona por turnos: el cliente envía primero y el servidor responde. La salida de consola confirma el funcionamiento del programa, pero la verificación visual del contenido de los paquetes de red con Wireshark/tcpdump está pendiente.

## Pruebas realizadas

Con el entorno virtual activo y desde la raíz del repositorio:

**1. X25519 y HKDF**

```bash
python 01_chat_cifrado/prueba_x25519.py
```

**Resultado esperado:** `Secretos iguales: True`, `Llaves AES iguales: True` y `Tamano de la llave AES: 256 bits`.

**2. Integridad AES-GCM**

```bash
python 01_chat_cifrado/prueba_integridad.py
```

**Resultado esperado:** se recupera correctamente el mensaje original; después de modificar un byte del texto cifrado, AES-GCM detecta la alteración y rechaza el descifrado (`InvalidTag`). Esta prueba verifica la integridad del cifrado, **no la identidad de los participantes**.

Las salidas obtenidas, comandos explicados y capturas están documentados en **[GUIA.md](GUIA.md)**. Las imágenes referenciadas allí deben conservar sus rutas relativas dentro de `capturas/`.

## Trabajo pendiente

- **Ed25519:** firmar mensajes y, especialmente, autenticar el intercambio X25519 mediante claves públicas de identidad conocidas o verificadas por un canal confiable.
- **MITM:** implementar la demostración controlada de sustitución de claves en la versión sin autenticación y el rechazo del ataque en la versión autenticada.
- **Captura de tráfico:** utilizar Wireshark o tcpdump para comprobar que los mensajes transmitidos no son legibles en la red.
- **Comparación criptográfica:** ejecutar las mediciones de RSA-3072, X25519 y ML-KEM-768 y generar tabla y gráfico.
- **Documentación final:** completar la guía, el análisis de resultados y los pasos de las nuevas prácticas.

## Seguridad y colaboración

- Usar solamente mensajes y datos de prueba. No introducir información personal o confidencial.
- No subir claves privadas, credenciales, tokens ni el entorno virtual `env/`.
- Cada integrante debe registrar sus propios cambios mediante commits en su rama y presentar un *Pull Request* para integrarlos en `main`.
- Las pruebas del ataque MITM deben ejecutarse exclusivamente en el entorno controlado del grupo.

## Documentación

Consultar [GUIA.md](GUIA.md) para el procedimiento detallado de instalación, explicación de comandos, ejecución y evidencias de las pruebas realizadas.
