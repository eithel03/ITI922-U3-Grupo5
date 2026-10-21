#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ITI-922 Seguridad de TI II
Grupo 5

Practica 2: Servidor AUTENTICADO (con firmas Ed25519).

Mismo protocolo que el servidor_vulnerable.py, pero
el intercambio X25519 se autentica con firmas
Ed25519 sobre la transcripcion completa (ambas llaves
publicas y el salt), igual que en la Practica 1.

Uso (terminal 1):
    python 02_ataque_mitm/servidor_autenticado.py

Requiere haber generado las identidades de la
Practica 1:
    python 01_chat_cifrado/generar_identidades.py
"""

import sys

from pathlib import Path

# Reutilizar los modulos de la Practica 1.
sys.path.insert(
    0,
    str(
        Path(__file__).resolve().parent.parent
        / "01_chat_cifrado"
    )
)

import socket

from cryptography.exceptions import InvalidTag

from criptografia import (
    generar_llaves,
    calcular_secreto,
    derivar_llave_aes,
    generar_salt,
    cifrar_mensaje,
    descifrar_mensaje
)

from autenticacion import (
    firmar_intercambio,
    verificar_intercambio
)

from comunicacion import enviar_datos, recibir_datos


HOST = "127.0.0.1"
PUERTO = 5000


def main():

    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    ) as servidor:

        servidor.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )

        servidor.bind((HOST, PUERTO))
        servidor.listen(1)

        print("[SERVIDOR] Esperando conexion...")

        conexion, direccion = servidor.accept()

        with conexion:

            print(
                f"[SERVIDOR] Cliente conectado: {direccion}"
            )

            try:

                # 1. Generar llaves X25519.
                privada, publica_servidor = generar_llaves()

                # 2. Enviar llave publica del servidor.
                enviar_datos(conexion, publica_servidor)

                # 3. Recibir llave publica del cliente.
                publica_cliente = recibir_datos(conexion)

                # 4. Generar salt.
                salt = generar_salt()

                # 5. Enviar salt al cliente.
                enviar_datos(conexion, salt)

                # 6. Firmar intercambio con Ed25519.
                firma_servidor = firmar_intercambio(
                    "servidor",
                    publica_servidor,
                    publica_cliente,
                    salt
                )

                # 7. Enviar firma del servidor.
                enviar_datos(conexion, firma_servidor)

                print("[ED25519] Firma del servidor enviada.")

                # 8. Recibir firma del cliente.
                firma_cliente = recibir_datos(conexion)

                # 9. Verificar identidad del cliente.
                autenticado = verificar_intercambio(
                    "cliente",
                    publica_servidor,
                    publica_cliente,
                    salt,
                    firma_cliente
                )

                if not autenticado:
                    print("[SEGURIDAD] Firma del cliente invalida.")
                    raise ValueError(
                        "Autenticacion del cliente fallida"
                    )

                print("[ED25519] Cliente autenticado correctamente.")

                # 10. Calcular secreto compartido.
                secreto = calcular_secreto(
                    privada,
                    publica_cliente
                )

                # 11. Derivar llave AES.
                llave_aes = derivar_llave_aes(
                    secreto,
                    salt
                )

                print("[X25519] Intercambio autenticado.")
                print("[HKDF] Llave AES-256 derivada.")

                # 12. Confirmar autenticacion.
                confirmacion = cifrar_mensaje(
                    llave_aes,
                    "AUTENTICACION_OK"
                )

                enviar_datos(conexion, confirmacion)

                print("[AES-GCM] Comunicacion cifrada activa.")
                print("Escriba 'salir' para finalizar.\n")

                # 13. Iniciar chat.
                while True:

                    datos = recibir_datos(conexion)

                    mensaje = descifrar_mensaje(
                        llave_aes,
                        datos
                    )

                    print(f"\n[CLIENTE]: {mensaje}")

                    if mensaje.lower() == "salir":
                        break

                    respuesta = input("[SERVIDOR]: ")

                    cifrado = cifrar_mensaje(
                        llave_aes,
                        respuesta
                    )

                    enviar_datos(conexion, cifrado)

                    if respuesta.lower() == "salir":
                        break

            except (
                ConnectionError,
                ValueError,
                InvalidTag,
                OSError
            ) as error:

                print(f"[ERROR] {error}")

            except KeyboardInterrupt:

                print("\n[SERVIDOR] Interrumpido.")

            print("[SERVIDOR] Conexion cerrada.")


if __name__ == "__main__":
    main()
