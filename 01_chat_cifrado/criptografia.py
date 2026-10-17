#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Proyecto: Algoritmos asimetricos y post-cuanticos
Curso: ITI-922 Seguridad de TI II
Grupo: 5

Practica 1: Chat cifrado

Funcionalidades:
1. Generacion de llaves X25519.
2. Calculo del secreto compartido.
3. Derivacion de llaves AES mediante HKDF.
4. Cifrado y descifrado AES-256-GCM.
5. Generacion de llaves Ed25519.
6. Firma digital de mensajes.
7. Verificacion de firmas digitales.
"""

import os

from cryptography.exceptions import InvalidSignature

from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey
)

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey
)

from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat
)


# ==========================================================
# 1. GENERACION DE LLAVES X25519
# ==========================================================

def generar_llaves():
    """
    Genera un par de llaves X25519.

    La llave privada permanece en el dispositivo.
    La llave publica puede compartirse.

    Retorna:
        llave_privada
        llave_publica_bytes
    """

    # Generar llave privada X25519.
    llave_privada = X25519PrivateKey.generate()

    # Obtener llave publica.
    llave_publica = llave_privada.public_key()

    # Convertir llave publica a bytes.
    llave_publica_bytes = llave_publica.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw
    )

    return llave_privada, llave_publica_bytes


# ==========================================================
# 2. CALCULO DEL SECRETO COMPARTIDO
# ==========================================================

def calcular_secreto(llave_privada, llave_publica_remota):
    """
    Calcula un secreto compartido mediante X25519.

    Cada participante utiliza:
    - Su llave privada.
    - La llave publica del otro participante.
    """

    # Reconstruir la llave publica recibida.
    llave_remota = X25519PublicKey.from_public_bytes(
        llave_publica_remota
    )

    # Calcular secreto compartido.
    secreto = llave_privada.exchange(llave_remota)

    return secreto


# ==========================================================
# 3. DERIVACION DE LLAVE AES MEDIANTE HKDF
# ==========================================================

def derivar_llave_aes(secreto, salt):
    """
    Deriva una llave AES de 256 bits mediante HKDF.

    Utiliza:
    - SHA-256
    - Longitud de 32 bytes
    - Salt compartido
    """

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"ITI922-Grupo5-Chat"
    )

    return hkdf.derive(secreto)


# ==========================================================
# 4. GENERACION DE SALT
# ==========================================================

def generar_salt():
    """
    Genera 16 bytes aleatorios para HKDF.
    """

    return os.urandom(16)


# ==========================================================
# 5. CIFRADO AES-256-GCM
# ==========================================================

def cifrar_mensaje(llave_aes, mensaje):
    """
    Cifra un mensaje utilizando AES-256-GCM.

    Genera un nonce aleatorio de 12 bytes.

    Retorna:
        nonce + mensaje_cifrado + etiqueta
    """

    # Generar nonce aleatorio.
    nonce = os.urandom(12)

    # Crear objeto AES-GCM.
    aesgcm = AESGCM(llave_aes)

    # Cifrar mensaje.
    cifrado = aesgcm.encrypt(
        nonce,
        mensaje.encode("utf-8"),
        None
    )

    # Enviar nonce junto con el contenido cifrado.
    return nonce + cifrado


# ==========================================================
# 6. DESCIFRADO AES-256-GCM
# ==========================================================

def descifrar_mensaje(llave_aes, datos):
    """
    Descifra un mensaje AES-GCM.

    Verifica automaticamente la integridad.

    Si los datos fueron modificados,
    AES-GCM genera una excepcion InvalidTag.
    """

    # Extraer nonce.
    nonce = datos[:12]

    # Extraer mensaje cifrado y etiqueta.
    cifrado = datos[12:]

    # Crear objeto AES-GCM.
    aesgcm = AESGCM(llave_aes)

    # Descifrar mensaje.
    mensaje = aesgcm.decrypt(
        nonce,
        cifrado,
        None
    )

    return mensaje.decode("utf-8")


# ==========================================================
# 7. GENERACION DE LLAVES ED25519
# ==========================================================

def generar_llaves_ed25519():
    """
    Genera un par de llaves Ed25519.

    Ed25519 permite realizar firmas digitales.

    La llave privada se utiliza para firmar.
    La llave publica se utiliza para verificar.

    Retorna:
        llave_privada
        llave_publica_bytes
    """

    # Generar llave privada Ed25519.
    llave_privada = Ed25519PrivateKey.generate()

    # Obtener llave publica correspondiente.
    llave_publica = llave_privada.public_key()

    # Convertir llave publica a bytes.
    llave_publica_bytes = llave_publica.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw
    )

    return llave_privada, llave_publica_bytes


# ==========================================================
# 8. FIRMA DIGITAL ED25519
# ==========================================================

def firmar_mensaje(llave_privada, mensaje):
    """
    Firma digitalmente un mensaje utilizando Ed25519.

    Parametros:
        llave_privada: llave privada Ed25519.
        mensaje: contenido en formato bytes.

    Retorna:
        firma digital.
    """

    # Generar firma digital.
    firma = llave_privada.sign(mensaje)

    return firma


# ==========================================================
# 9. VERIFICACION DE FIRMA ED25519
# ==========================================================

def verificar_firma(llave_publica_bytes, mensaje, firma):
    """
    Verifica una firma digital Ed25519.

    Parametros:
        llave_publica_bytes: llave publica Ed25519.
        mensaje: mensaje original en bytes.
        firma: firma digital recibida.

    Retorna:
        True si la firma es valida.
        False si la firma es incorrecta.
    """

    # Reconstruir llave publica Ed25519.
    llave_publica = Ed25519PublicKey.from_public_bytes(
        llave_publica_bytes
    )

    try:

        # Verificar firma digital.
        llave_publica.verify(
            firma,
            mensaje
        )

        return True

    except InvalidSignature:

        # La firma no corresponde al mensaje.
        return False
