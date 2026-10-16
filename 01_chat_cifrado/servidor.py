#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket

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

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as servidor:

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

            print(f"[SERVIDOR] Cliente conectado: {direccion}")

            try:
                # Generar llaves X25519.
                privada, publica = generar_llaves()

                # Intercambiar llaves publicas.
                enviar_datos(conexion, publica)
                publica_cliente = recibir_datos(conexion)

                # Calcular secreto compartido.
                secreto = calcular_secreto(
                    privada,
                    publica_cliente
                )

                # Generar y transmitir salt.
                salt = generar_salt()
                enviar_datos(conexion, salt)

                # Derivar llave AES.
                llave_aes = derivar_llave_aes(
                    secreto,
                    salt
                )

                print("[X25519] Intercambio completado.")
                print("[HKDF] Llave AES-256 derivada.")

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

            except (ConnectionError, ValueError) as error:
                print(f"[ERROR] {error}")

            except KeyboardInterrupt:
                print("\n[SERVIDOR] Interrumpido.")

            print("[SERVIDOR] Conexion cerrada.")


if __name__ == "__main__":
    main()
