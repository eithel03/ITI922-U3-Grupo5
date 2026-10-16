#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket

from criptografia import (
    generar_llaves,
    calcular_secreto,
    derivar_llave_aes,
    cifrar_mensaje,
    descifrar_mensaje
)

from comunicacion import enviar_datos, recibir_datos


HOST = "127.0.0.1"
PUERTO = 5000


def main():

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cliente:

            cliente.connect((HOST, PUERTO))

            print("[CLIENTE] Conexion establecida.")

            # Generar llaves X25519.
            privada, publica = generar_llaves()

            # Intercambiar llaves publicas.
            publica_servidor = recibir_datos(cliente)
            enviar_datos(cliente, publica)

            # Calcular secreto compartido.
            secreto = calcular_secreto(
                privada,
                publica_servidor
            )

            # Recibir salt.
            salt = recibir_datos(cliente)

            # Derivar llave AES.
            llave_aes = derivar_llave_aes(
                secreto,
                salt
            )

            print("[X25519] Intercambio completado.")
            print("[HKDF] Llave AES-256 derivada.")
            print("[AES-GCM] Comunicacion cifrada activa.")
            print("Escriba 'salir' para finalizar.\n")

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

    except (ConnectionError, ConnectionRefusedError, ValueError) as error:
        print(f"[ERROR] {error}")

    except KeyboardInterrupt:
        print("\n[CLIENTE] Interrumpido.")

    print("[CLIENTE] Conexion cerrada.")


if __name__ == "__main__":
    main()
