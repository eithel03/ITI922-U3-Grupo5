#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ITI-922 Seguridad de TI II
Grupo 5

Practica 2: Cliente VULNERABLE (sin firmas Ed25519).

Cliente sin autenticacion del intercambio.

IMPORTANTE: este cliente se conecta al puerto 5001,
que es donde escucha el atacante MITM. El cliente
NO sabe que esta hablando con un intermediario;
cree que habla directamente con el servidor.

Uso (terminal 3):
    python 02_ataque_mitm/cliente_vulnerable.py
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
    cifrar_mensaje,
    descifrar_mensaje
)

from comunicacion import enviar_datos, recibir_datos


HOST = "127.0.0.1"

# Puerto del atacante MITM.
# En un ataque real el cliente no conoce
# este detalle: solo busca un servidor.
PUERTO = 5001


def main():

    try:

        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as cliente:

            cliente.connect((HOST, PUERTO))

            print("[CLIENTE] Conexion establecida.")

            # 1. Generar llaves X25519.
            privada, publica_cliente = generar_llaves()

            # 2. Recibir llave publica del "servidor".
            publica_servidor = recibir_datos(cliente)

            # 3. Enviar llave publica del cliente.
            enviar_datos(cliente, publica_cliente)

            # 4. Recibir salt.
            salt = recibir_datos(cliente)

            # 5. Calcular secreto compartido.
            # NOTA: sin firmas Ed25519 no se verifica
            # que la llave publica recibida pertenezca
            # realmente al servidor esperado.
            secreto = calcular_secreto(
                privada,
                publica_servidor
            )

            # 6. Derivar llave AES.
            llave_aes = derivar_llave_aes(
                secreto,
                salt
            )

            print("[X25519] Secreto calculado.")
            print("[HKDF] Llave AES-256 derivada.")

            # 7. Esperar confirmacion del servidor.
            datos = recibir_datos(cliente)

            confirmacion = descifrar_mensaje(
                llave_aes,
                datos
            )

            if confirmacion != "AUTENTICACION_OK":

                raise ValueError(
                    "Confirmacion de sesion invalida"
                )

            print("[AES-GCM] Comunicacion cifrada activa.")
            print("Escriba 'salir' para finalizar.\n")

            # 8. Iniciar chat.
            while True:

                mensaje = input("[CLIENTE]: ")

                cifrado = cifrar_mensaje(
                    llave_aes,
                    mensaje
                )

                enviar_datos(cliente, cifrado)

                if mensaje.lower() == "salir":
                    break

                datos = recibir_datos(cliente)

                respuesta = descifrar_mensaje(
                    llave_aes,
                    datos
                )

                print(f"[SERVIDOR]: {respuesta}")

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

        print("\n[CLIENTE] Interrumpido.")

    print("[CLIENTE] Conexion cerrada.")


if __name__ == "__main__":
    main()
