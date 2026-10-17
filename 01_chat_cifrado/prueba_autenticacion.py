#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Universidad Tecnica Nacional
ITI-922 Seguridad de TI II
Grupo 5

Prueba de autenticacion Ed25519.

Objetivos:
1. Comprobar una firma legitima.
2. Rechazar una identidad falsa.
3. Detectar una llave X25519 modificada.
4. Detectar un salt modificado.
"""

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)

from criptografia import (
    generar_llaves,
    generar_salt
)

from autenticacion import (
    firmar_intercambio,
    verificar_intercambio,
    construir_transcripcion
)


def main():

    print("=== PRUEBA DE AUTENTICACION ED25519 ===\n")

    # Generar llaves X25519 de prueba.
    _, publica_servidor = generar_llaves()
    _, publica_cliente = generar_llaves()

    salt = generar_salt()

    # ==========================================
    # PRUEBA 1: IDENTIDAD LEGITIMA
    # ==========================================

    firma_legitima = firmar_intercambio(
        "servidor",
        publica_servidor,
        publica_cliente,
        salt
    )

    resultado = verificar_intercambio(
        "servidor",
        publica_servidor,
        publica_cliente,
        salt,
        firma_legitima
    )

    print("[1] Firma legitima aceptada:", resultado)

    assert resultado is True

    # ==========================================
    # PRUEBA 2: IDENTIDAD FALSA
    # ==========================================

    atacante = Ed25519PrivateKey.generate()

    transcripcion = construir_transcripcion(
        publica_servidor,
        publica_cliente,
        salt
    )

    datos = b"servidor" + transcripcion

    firma_atacante = atacante.sign(datos)

    resultado_falso = verificar_intercambio(
        "servidor",
        publica_servidor,
        publica_cliente,
        salt,
        firma_atacante
    )

    print(
        "[2] Identidad falsa aceptada:",
        resultado_falso
    )

    assert resultado_falso is False

    # ==========================================
    # PRUEBA 3: LLAVE X25519 MODIFICADA
    # ==========================================

    _, publica_modificada = generar_llaves()

    resultado_modificado = verificar_intercambio(
        "servidor",
        publica_modificada,
        publica_cliente,
        salt,
        firma_legitima
    )

    print(
        "[3] Intercambio modificado aceptado:",
        resultado_modificado
    )

    assert resultado_modificado is False

    # ==========================================
    # PRUEBA 4: SALT MODIFICADO
    # ==========================================

    salt_modificado = generar_salt()

    resultado_salt = verificar_intercambio(
        "servidor",
        publica_servidor,
        publica_cliente,
        salt_modificado,
        firma_legitima
    )

    print(
        "[4] Salt modificado aceptado:",
        resultado_salt
    )

    assert resultado_salt is False

    print("\n[OK] Todas las pruebas fueron exitosas.")
    print("[SEGURIDAD] Identidades falsas rechazadas.")
    print("[SEGURIDAD] Manipulaciones detectadas.")

    print("\n=== PRUEBA FINALIZADA ===")


if __name__ == "__main__":
    main()
