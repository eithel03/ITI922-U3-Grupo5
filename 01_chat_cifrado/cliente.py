#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ITI-922 Seguridad de TI II
Grupo 5

Cliente de chat cifrado y autenticado.

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

    try:

        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as cliente:

            cliente.connect((HOST, PUERTO))

            print("[CLIENTE] Conexion establecida.")

            # 1. Generar llaves X25519.
            privada, publica_cliente = generar_llaves()

            # 2. Recibir llave publica del servidor.
            publica_servidor = recibir_datos(cliente)

            # 3. Enviar llave publica del cliente.
            enviar_datos(cliente, publica_cliente)

            # 4. Recibir salt.
            salt = recibir_datos(cliente)

            # 5. Recibir firma del servidor.
            firma_servidor = recibir_datos(cliente)

            # 6. Verificar firma del servidor.
            autenticado = verificar_intercambio(
                "servidor",
                publica_servidor,
                publica_cliente,
                salt,
                firma_servidor
            )

            if not autenticado:

                print(
                    "[SEGURIDAD] Firma del servidor invalida."
                )

                raise ValueError(
                    "Autenticacion del servidor fallida"
                )

            print(
                "[ED25519] Servidor autenticado correctamente."
            )

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

            # 12. Preparar firmas individuales.
            #
            # La transcripcion identifica esta sesion.
            # Los contadores evitan aceptar mensajes
            # repetidos o fuera de orden.

            transcripcion = construir_transcripcion(
                publica_servidor,
                publica_cliente,
                salt
            )

            enviados = 0
            recibidos = 0

            # 13. Iniciar chat.
            while True:

                mensaje = input("[CLIENTE]: ")

                # Firmar individualmente el mensaje.
                sobre = firmar_chat(
                    "cliente",
                    mensaje,
                    transcripcion,
                    enviados
                )

                # Cifrar mensaje y firma con AES-GCM.
                cifrado = cifrar_mensaje(
                    llave_aes,
                    sobre
                )

                # Enviar datos cifrados.
                enviar_datos(cliente, cifrado)

                enviados += 1

                print(
                    "[ED25519] Mensaje firmado y enviado."
                )

                if mensaje.lower() == "salir":
                    break

                # Recibir respuesta cifrada.
                datos = recibir_datos(cliente)

                # Descifrar sobre firmado.
                sobre_remoto = descifrar_mensaje(
                    llave_aes,
                    datos
                )

                # Verificar firma del servidor.
                respuesta = verificar_chat(
                    "servidor",
                    sobre_remoto,
                    transcripcion,
                    recibidos
                )

                recibidos += 1

                print(
                    "[ED25519] Firma del mensaje "
                    "del servidor valida."
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
