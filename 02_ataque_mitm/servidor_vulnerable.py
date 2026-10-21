#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ITI-922 Seguridad de TI II
Grupo 5

Practica 2: Servidor VULNERABLE (sin firmas Ed25519).

Este servidor usa el mismo esquema hibrido de la
Practica 1 (X25519 + HKDF + AES-256-GCM), pero NO
autentica el intercambio de llaves con firmas.

Por eso un atacante MITM puede sustituir las llaves
X25519, establecer dos sesiones independientes y
leer todos los mensajes.

Uso (terminal 1):
    python 02_ataque_mitm/servidor_vulnerable.py
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

                # 6. Calcular secreto compartido.
                # NOTA: sin firmas Ed25519 no se verifica
                # que la llave publica recibida pertenezca
                # realmente al cliente esperado.
                secreto = calcular_secreto(
                    privada,
                    publica_cliente
                )

                # 7. Derivar llave AES.
                llave_aes = derivar_llave_aes(
                    secreto,
                    salt
                )

                print("[X25519] Secreto calculado.")
                print("[HKDF] Llave AES-256 derivada.")

                # 8. Confirmar inicio de sesion.
                confirmacion = cifrar_mensaje(
                    llave_aes,
                    "AUTENTICACION_OK"
                )

                enviar_datos(conexion, confirmacion)

                print("[AES-GCM] Comunicacion cifrada activa.")
                print("Escriba 'salir' para finalizar.\n")

                # 9. Iniciar chat.
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
