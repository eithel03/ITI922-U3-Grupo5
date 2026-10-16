#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey
)

from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat
)


def generar_llaves():
    # Generar una llave privada X25519.
    llave_privada = X25519PrivateKey.generate()

    # Obtener su correspondiente llave publica.
    llave_publica = llave_privada.public_key()

    # Convertir la llave publica a bytes para transmitirla.
    llave_publica_bytes = llave_publica.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw
    )

    return llave_privada, llave_publica_bytes


def calcular_secreto(llave_privada, llave_publica_remota):
    # Reconstruir la llave publica recibida.
    llave_remota = X25519PublicKey.from_public_bytes(
        llave_publica_remota
    )

    # Calcular el secreto compartido con X25519.
    secreto = llave_privada.exchange(llave_remota)

    return secreto


def derivar_llave_aes(secreto, salt):
    # Derivar una llave AES de 32 bytes mediante HKDF.
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"ITI922-Grupo5-Chat"
    )

    return hkdf.derive(secreto)


def generar_salt():
    # Generar 16 bytes aleatorios para HKDF.
    return os.urandom(16)
