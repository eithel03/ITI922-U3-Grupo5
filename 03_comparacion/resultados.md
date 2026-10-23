# Comparación de algoritmos criptográficos

Promedio de 10 ejecuciones por algoritmo.

| Algoritmo | Formato de clave pública | Clave pública (bytes) | Bytes del intercambio modelado | Generación de claves (ms) | Operación principal (ms) |
|---|---|---:|---:|---:|---:|
| RSA-3072 | DER/SPKI | 422 | 806 | 646.4936 | 1.0479 |
| X25519 | Raw | 32 | 64 | 19.7331 | 0.2245 |
| ML-KEM-768 | Raw | 1184 | 2272 | 0.5421 | 0.1920 |

## Interpretación de los datos

- RSA-3072: se cuentan la clave pública en DER/SPKI y el cifrado RSA-OAEP de un secreto de 32 bytes.
- X25519: se cuentan las dos claves públicas raw intercambiadas para calcular un secreto compartido.
- ML-KEM-768: se cuentan la clave pública raw y el texto cifrado de encapsulación.

Los bytes calculados corresponden a mensajes criptográficos modelados; no incluyen cabeceras TCP/IP, TLS ni metadatos de red.

La captura de Wireshark se realizará por separado para observar el tráfico real.

Los tiempos de operación no son totalmente equivalentes: RSA cifra un secreto, X25519 calcula un secreto compartido y ML-KEM encapsula un secreto.

Los resultados pueden variar según el equipo y la carga del sistema.