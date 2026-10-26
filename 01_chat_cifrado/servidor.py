#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ITI-922 Seguridad de TI II
Grupo 5

Servidor de chat cifrado y autenticado.

X25519: intercambio de llaves.
Ed25519: autenticacion y firma de mensajes.
HKDF: derivacion de llave.
AES-256-GCM: cifrado de mensajes.
"""

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
    verificar_intercambio,
    construir_transcripcion,
    firmar_chat,
    verificar_chat
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
                enviar_datos(
                    conexion,
                    publica_servidor
                )

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
                enviar_datos(
                    conexion,
                    firma_servidor
                )

                print(
                    "[ED25519] Firma del servidor enviada."
                )

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

                    print(
                        "[SEGURIDAD] Firma del cliente invalida."
                    )

                    raise ValueError(
                        "Autenticacion del cliente fallida"
                    )

                print(
                    "[ED25519] Cliente autenticado correctamente."
                )

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

                enviar_datos(
                    conexion,
                    confirmacion
                )

                print(
                    "[AES-GCM] Comunicacion cifrada activa."
                )

                print(
                    "Escriba 'salir' para finalizar.\n"
                )

                # 13. Preparar firmas individuales.
                #
                # Vincular las firmas a la sesion.
                # Los contadores permiten detectar
                # mensajes repetidos o fuera de orden.

                transcripcion = construir_transcripcion(
                    publica_servidor,
                    publica_cliente,
                    salt
                )

                enviados = 0
                recibidos = 0

                # 14. Iniciar chat.
                while True:

                    # Recibir mensaje cifrado.
                    datos = recibir_datos(conexion)

                    # Descifrar mensaje y firma.
                    sobre_remoto = descifrar_mensaje(
                        llave_aes,
                        datos
                    )

                    # Verificar firma del cliente.
                    mensaje = verificar_chat(
                        "cliente",
                        sobre_remoto,
                        transcripcion,
                        recibidos
                    )

                    recibidos += 1

                    print(
                        "[ED25519] Firma del mensaje "
                        "del cliente valida."
                    )

                    print(f"\n[CLIENTE]: {mensaje}")

                    if mensaje.lower() == "salir":
                        break

                    # Preparar respuesta.
                    respuesta = input("[SERVIDOR]: ")

                    # Firmar individualmente la respuesta.
                    sobre = firmar_chat(
                        "servidor",
                        respuesta,
                        transcripcion,
                        enviados
                    )

                    # Cifrar respuesta y firma.
                    cifrado = cifrar_mensaje(
                        llave_aes,
                        sobre
                    )

                    # Enviar respuesta cifrada.
                    enviar_datos(
                        conexion,
                        cifrado
                    )

                    enviados += 1

                    print(
                        "[ED25519] Respuesta firmada y enviada."
                    )

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
