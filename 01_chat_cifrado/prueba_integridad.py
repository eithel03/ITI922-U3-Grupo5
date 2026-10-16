#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from criptografia import cifrar_mensaje, descifrar_mensaje


def main():

    print("=== PRUEBA DE INTEGRIDAD AES-GCM ===\n")

    # Generar una llave AES de 256 bits.
    llave = AESGCM.generate_key(bit_length=256)

    # Mensaje original.
    mensaje = "Transferir 1000 colones"

    # Cifrar el mensaje.
    cifrado = cifrar_mensaje(llave, mensaje)

    print("[1] Mensaje original:", mensaje)
    print("[2] Mensaje cifrado:", cifrado.hex())

    # Descifrar el mensaje original.
    descifrado = descifrar_mensaje(llave, cifrado)

    print("[3] Mensaje descifrado:", descifrado)

    # Simular una modificacion del mensaje cifrado.
    manipulado = bytearray(cifrado)

    # Modificar un byte del texto cifrado.
    manipulado[12] ^= 1

    print("\n[4] Mensaje cifrado manipulado.")

    # Intentar descifrar el mensaje modificado.
    try:
        descifrar_mensaje(llave, bytes(manipulado))

        print("[ERROR] La manipulacion no fue detectada.")

    except InvalidTag:
        print("[5] Manipulacion detectada correctamente.")
        print("[6] AES-GCM rechazo el mensaje alterado.")

    print("\n=== PRUEBA FINALIZADA ===")


if __name__ == "__main__":
    main()
