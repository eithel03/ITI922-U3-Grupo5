# ITI922-U3-Grupo5

**Proyecto de algoritmos asimétricos y post-cuánticos — Seguridad de TI II**  
**Universidad Técnica Nacional | Curso ITI-922 | Unidad III: Sistemas de alta seguridad**

**Integrantes:** Eithel, Luis Diego, Rafa y Vanessa.

## Descripción

Este repositorio reúne las prácticas del Grupo 5 sobre criptografía asimétrica y post-cuántica. El objetivo es comprender cómo se establece una clave compartida, cómo se protegen los mensajes y por qué debe autenticarse el intercambio de claves para impedir ataques de intermediario (*man-in-the-middle*, MITM).

El proyecto contempla tres actividades:

1. **Chat cifrado:** comunicación TCP entre cliente y servidor con X25519, HKDF, AES-256-GCM y autenticación mutua del intercambio mediante firmas Ed25519.
2. **Demostración MITM:** mostrar el riesgo del intercambio no autenticado y cómo impedir la suplantación mediante autenticación de claves.
3. **Comparación clásica y post-cuántica:** medir RSA-3072, X25519 y ML-KEM-768 (tamaño de clave pública, datos enviados y tiempos de operación), y presentar tabla y gráfico.

> **Estado verificado de la Práctica 1:** chat TCP local operativo con X25519, HKDF-SHA-256, AES-256-GCM y autenticación mutua Ed25519 del intercambio de claves. Se ejecutaron pruebas de integridad, firmas, rechazo de identidad falsa y manipulación del intercambio, además de una captura Wireshark del tráfico cifrado.

## Estructura del repositorio

```text
ITI922-U3-Grupo5/
├── 01_chat_cifrado/
│   ├── servidor.py                 # Servidor TCP autenticado y cifrado
│   ├── cliente.py                  # Cliente TCP autenticado y cifrado
│   ├── comunicacion.py             # Tramas con longitud prefijada
│   ├── criptografia.py             # X25519, HKDF, AES-GCM y Ed25519
│   ├── autenticacion.py            # Firma/verificación del intercambio
│   ├── generar_identidades.py      # Identidades locales Ed25519
│   ├── prueba_x25519.py
│   ├── prueba_integridad.py
│   ├── prueba_ed25519.py
│   └── prueba_autenticacion.py
├── 02_ataque_mitm/                 # Material de la Práctica 2
├── 03_comparacion/                 # Material de la Práctica 3
├── capturas/                      # Evidencias de las pruebas
├── GUIA.md                        # Procedimiento y resultados detallados
├── requirements.txt
├── .gitignore
└── README.md
```

Las identidades privadas se guardan localmente en `01_chat_cifrado/identidades/`, carpeta excluida de Git mediante `.gitignore`. Las prácticas 2 y 3 son actividades independientes de la implementación documentada aquí; no se afirma su ejecución.

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

El servidor y el cliente intercambian claves públicas efímeras X25519; el intercambio y sus parámetros se autentican con firmas Ed25519. Tras verificar las identidades, ambos calculan el secreto compartido y derivan una clave AES de 256 bits con HKDF-SHA-256. Los mensajes se cifran y autentican con AES-GCM. La aplicación funciona **por turnos**: primero escribe el cliente, después responde el servidor. Para cerrar normalmente, escribir `salir`.

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

![Datos cifrados observados en Wireshark](capturas/10_datos_cifrados_aes_gcm.png)

El registro completo se encuentra en [`capturas/chat_cifrado_grupo5.pcapng`](capturas/chat_cifrado_grupo5.pcapng). Para el procedimiento detallado y todas las imágenes, consultar **[GUIA.md](GUIA.md)**.

## Alcance y limitaciones de la Práctica 1

La autenticación Ed25519 se aplica al **intercambio de claves**, mientras que AES-GCM proporciona confidencialidad e integridad a los mensajes posteriores. Las pruebas no acreditan firmas Ed25519 independientes sobre cada mensaje ni constituyen una demostración completa de MITM. La confianza en las claves públicas de identidad depende de su provisión previa por un medio confiable. La ejecución comprobada es local (`127.0.0.1:5000`), con una conexión y comunicación por turnos. No se recomienda usar el prototipo con información sensible ni considerarlo listo para producción.

## Seguridad y colaboración

- Usar solamente mensajes y datos de prueba. No introducir información personal o confidencial.
- No subir claves privadas, credenciales, tokens ni el entorno virtual `env/`.
- Cada integrante debe registrar sus propios cambios mediante commits en su rama y presentar un *Pull Request* para integrarlos en `main`.
- Las pruebas del ataque MITM deben ejecutarse exclusivamente en el entorno controlado del grupo.

## Documentación

Consultar [GUIA.md](GUIA.md) para el procedimiento detallado de instalación, explicación de comandos, ejecución y evidencias de las pruebas realizadas.
