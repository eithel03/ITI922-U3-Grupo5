#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ITI-922 Seguridad de TI II
Grupo 5

Practica 2: Cliente AUTENTICADO (con firmas Ed25519).

Cliente con autenticacion mutua del intercambio,
igual que en la Practica 1.

IMPORTANTE: este cliente se conecta al puerto 5001,
que es donde escucha el atacante MITM. Cuando el
atacante sustituye las llaves X25519, la firma
Ed25519 ya no coincide con la transcripcion y el
cliente rechaza la sesion.

Uso (terminal 3):
    python 02_ataque_mitm/cliente_autenticado.py
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

from autenticacion import (
    firmar_intercambio,
    verificar_intercambio
)

from comunicacion import enviar_datos, recibir_datos


HOST = "127.0.0.1"

# Puerto del atacante MITM.
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

            # 5. Recibir firma del "servidor".
            firma_servidor = recibir_datos(cliente)

            # 6. Verificar firma del servidor.
            # Si un atacante sustituyo la llave
            # X25519, la transcripcion no coincide
            # con la firma y la verificacion falla.
            autenticado = verificar_intercambio(
                "servidor",
                publica_servidor,
                publica_cliente,
                salt,
                firma_servidor
            )

            if not autenticado:

                print("[SEGURIDAD] Firma del servidor invalida.")

                raise ValueError(
                    "Autenticacion del servidor fallida"
                )

            print("[ED25519] Servidor autenticado correctamente.")

            # 7. Firmar intercambio como cliente.
            firma_cliente = firmar_intercambio(
                "cliente",
                publica_servidor,
                publica_cliente,
                salt
            )

            # 8. Enviar firma al servidor.
            enviar_datos(cliente, firma_cliente)

            print("[ED25519] Firma del cliente enviada.")

            # 9. Calcular secreto compartido.
            secreto = calcular_secreto(
                privada,
                publica_servidor
            )

            # 10. Derivar llave AES.
            llave_aes = derivar_llave_aes(
                secreto,
                salt
            )

            print("[X25519] Intercambio autenticado.")
            print("[HKDF] Llave AES-256 derivada.")

            # 11. Esperar confirmacion del servidor.
            datos = recibir_datos(cliente)

            confirmacion = descifrar_mensaje(
                llave_aes,
                datos
            )

            if confirmacion != "AUTENTICACION_OK":

                raise ValueError(
                    "Confirmacion de autenticacion invalida"
                )

            print("[ED25519] Autenticacion mutua completada.")
            print("[AES-GCM] Comunicacion cifrada activa.")
            print("Escriba 'salir' para finalizar.\n")

            # 12. Iniciar chat.
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
