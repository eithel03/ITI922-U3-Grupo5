#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Grupo 5 - Seguridad de TI II

Autenticacion de intercambio X25519
mediante firmas digitales Ed25519.

Tambien permite firmar y verificar
individualmente cada mensaje del chat.
"""

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)

from criptografia import (
    firmar_mensaje,
    verificar_firma
)


DIRECTORIO = Path(__file__).resolve().parent / "identidades"

CONTEXTO = b"ITI922-GRUPO5-X25519-AUTENTICADO-V1"


# ==========================================================
# 1. CARGAR IDENTIDADES ED25519
# ==========================================================

def cargar_privada(nombre):

    ruta = DIRECTORIO / f"{nombre}_privada.key"

    datos = ruta.read_bytes()

    return Ed25519PrivateKey.from_private_bytes(datos)


def cargar_publica(nombre):

    ruta = DIRECTORIO / f"{nombre}_publica.key"

    datos = ruta.read_bytes()

    if len(datos) != 32:
        raise ValueError("Llave publica Ed25519 invalida")

    return datos


# ==========================================================
# 2. CONSTRUIR TRANSCRIPCION DEL INTERCAMBIO
# ==========================================================

def construir_transcripcion(
    publica_servidor,
    publica_cliente,
    salt
):
    """
    Construye los datos que ambos participantes
    deben autenticar.

    Incluye:
    - Contexto del protocolo.
    - Llave X25519 del servidor.
    - Llave X25519 del cliente.
    - Salt utilizado por HKDF.
    """

    if len(publica_servidor) != 32:
        raise ValueError("Llave X25519 del servidor invalida")

    if len(publica_cliente) != 32:
        raise ValueError("Llave X25519 del cliente invalida")

    if len(salt) != 16:
        raise ValueError("Salt invalido")

    return (
        CONTEXTO
        + publica_servidor
        + publica_cliente
        + salt
    )


# ==========================================================
# 3. FIRMAR INTERCAMBIO X25519
# ==========================================================

def firmar_intercambio(
    nombre,
    publica_servidor,
    publica_cliente,
    salt
):
    """
    Firma la transcripcion del intercambio
    utilizando la identidad Ed25519.
    """

    privada = cargar_privada(nombre)

    transcripcion = construir_transcripcion(
        publica_servidor,
        publica_cliente,
        salt
    )

    # Incluir el rol del firmante.
    datos = nombre.encode("utf-8") + transcripcion

    return firmar_mensaje(privada, datos)


# ==========================================================
# 4. VERIFICAR INTERCAMBIO X25519
# ==========================================================

def verificar_intercambio(
    nombre,
    publica_servidor,
    publica_cliente,
    salt,
    firma
):
    """
    Verifica la firma del intercambio.

    La llave publica Ed25519 debe ser
    previamente confiable.
    """

    publica_identidad = cargar_publica(nombre)

    transcripcion = construir_transcripcion(
        publica_servidor,
        publica_cliente,
        salt
    )

    datos = nombre.encode("utf-8") + transcripcion

    return verificar_firma(
        publica_identidad,
        datos,
        firma
    )


# ==========================================================
# 5. CONTEXTO PARA FIRMAS INDIVIDUALES DEL CHAT
# ==========================================================

CONTEXTO_CHAT = b"ITI922-GRUPO5-CHAT-FIRMADO-V1"


def _datos_firma_chat(nombre, mensaje, transcripcion, numero):
    """
    Construye los datos que se firmaran.

    La firma incluye:
    - Contexto del chat.
    - Identidad del emisor.
    - Transcripcion del intercambio X25519.
    - Numero de secuencia.
    - Contenido del mensaje.

    Esto vincula cada firma con la sesion
    y con un mensaje especifico.
    """

    if nombre not in ("cliente", "servidor"):
        raise ValueError("Rol de firmante invalido")

    if not isinstance(mensaje, str):
        raise ValueError("El mensaje debe ser texto")

    if type(numero) is not int or not (0 <= numero < 2**64):
        raise ValueError("Numero de mensaje invalido")

    return (
        CONTEXTO_CHAT
        + b"\x00"
        + nombre.encode("ascii")
        + b"\x00"
        + transcripcion
        + numero.to_bytes(8, "big")
        + mensaje.encode("utf-8")
    )


# ==========================================================
# 6. FIRMAR CADA MENSAJE DEL CHAT
# ==========================================================

def firmar_chat(nombre, mensaje, transcripcion, numero):
    """
    Firma individualmente un mensaje mediante Ed25519.

    Devuelve un sobre JSON que contiene:
    - Version del formato.
    - Numero de secuencia.
    - Mensaje original.
    - Firma digital.

    Este sobre posteriormente se cifra
    utilizando AES-GCM.
    """

    datos = _datos_firma_chat(
        nombre,
        mensaje,
        transcripcion,
        numero
    )

    firma = firmar_mensaje(
        cargar_privada(nombre),
        datos
    )

    sobre = {
        "version": 1,
        "numero": numero,
        "mensaje": mensaje,
        "firma": base64.b64encode(firma).decode("ascii")
    }

    return json.dumps(
        sobre,
        ensure_ascii=True,
        separators=(",", ":")
    )


# ==========================================================
# 7. VERIFICAR FIRMA DE CADA MENSAJE
# ==========================================================

def verificar_chat(
    nombre,
    sobre,
    transcripcion,
    numero_esperado
):
    """
    Verifica la firma digital de un mensaje.

    Comprueba:
    - Formato del mensaje.
    - Version del protocolo.
    - Numero de secuencia.
    - Identidad del emisor.
    - Contenido firmado.
    - Firma Ed25519.

    Devuelve el mensaje si la firma es valida.
    Rechaza el mensaje si la verificacion falla.
    """

    try:

        obj = json.loads(sobre)

        campos = {
            "version",
            "numero",
            "mensaje",
            "firma"
        }

        if not isinstance(obj, dict) or set(obj) != campos:
            raise ValueError(
                "Formato del mensaje firmado invalido"
            )

        if type(obj["version"]) is not int or obj["version"] != 1:
            raise ValueError(
                "Version de mensaje firmado invalida"
            )

        if (
            type(obj["numero"]) is not int
            or obj["numero"] != numero_esperado
        ):
            raise ValueError(
                "Secuencia de mensaje invalida"
            )

        mensaje = obj["mensaje"]

        if not isinstance(mensaje, str):
            raise ValueError(
                "Mensaje firmado invalido"
            )

        firma = base64.b64decode(
            obj["firma"],
            validate=True
        )

        if len(firma) != 64:
            raise ValueError(
                "Longitud de firma Ed25519 invalida"
            )

        datos = _datos_firma_chat(
            nombre,
            mensaje,
            transcripcion,
            numero_esperado
        )

        publica = cargar_publica(nombre)

        if not verificar_firma(publica, datos, firma):
            raise ValueError(
                "Firma Ed25519 del mensaje invalida"
            )

        return mensaje

    except (
        TypeError,
        KeyError,
        json.JSONDecodeError
    ) as error:

        raise ValueError(
            "Sobre de mensaje firmado incorrecto"
        ) from error
