#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Grupo 5 - Seguridad de TI II

Autenticacion de intercambio X25519
mediante firmas digitales Ed25519.
"""

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
