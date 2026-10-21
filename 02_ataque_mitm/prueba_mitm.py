#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ITI-922 Seguridad de TI II
Grupo 5

Prueba automatica del ataque MITM (sin red).

Se comprueba:
1. Sin firmas: el atacante termina dos sesiones
   X25519 y descifra el mensaje del cliente.
2. Con firmas: el atacante no puede firmar la
   transcripcion con la identidad del servidor.
3. Con firmas: la firma legitima deja de ser
   valida cuando el atacante sustituye una llave.
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

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)

from criptografia import (
    generar_llaves,
    calcular_secreto,
    derivar_llave_aes,
    generar_salt,
    cifrar_mensaje,
    descifrar_mensaje,
    firmar_mensaje
)

from autenticacion import (
    firmar_intercambio,
    verificar_intercambio,
    construir_transcripcion
)


def main():

    print("=== PRUEBA DE ATAQUE MITM ===\n")

    # ==========================================
    # PARTE 1: PROTOCOLO SIN FIRMAS
    # El cliente piensa que habla con el
    # servidor, pero el atacante termina el
    # intercambio por ambos lados.
    # ==========================================

    print("--- Parte 1: protocolo SIN firmas ---")

    # El "servidor" real genera su par.
    privada_servidor, publica_servidor = generar_llaves()

    # El cliente genera su par.
    privada_cliente, publica_cliente = generar_llaves()

    # El atacante genera DOS pares distintos.
    privada_a, publica_a = generar_llaves()
    privada_b, publica_b = generar_llaves()

    salt = generar_salt()

    # Secreto real que el servidor cree tener
    # con el cliente (en realidad es con la
    # llave B del atacante).
    secreto_servidor = calcular_secreto(
        privada_servidor,
        publica_b
    )

    # Secreto real que el cliente cree tener
    # con el servidor (en realidad es con la
    # llave A del atacante).
    secreto_cliente = calcular_secreto(
        privada_cliente,
        publica_a
    )

    # Secretos que el atacante calcula.
    secreto_mitm_srv = calcular_secreto(
        privada_b,
        publica_servidor
    )

    secreto_mitm_cli = calcular_secreto(
        privada_a,
        publica_cliente
    )

    print(
        "[1] Secreto cliente == secreto servidor:",
        secreto_cliente == secreto_servidor
    )

    assert secreto_cliente != secreto_servidor, (
        "Sin ataque, los secretos deberian coincidir"
    )

    print(
        "[2] El atacante comparte secreto "
        "con el servidor:",
        secreto_mitm_srv == secreto_servidor
    )

    assert secreto_mitm_srv == secreto_servidor

    print(
        "[3] El atacante comparte secreto "
        "con el cliente:",
        secreto_mitm_cli == secreto_cliente
    )

    assert secreto_mitm_cli == secreto_cliente

    # El cliente cifra un mensaje pensando que
    # solo el servidor puede leerlo.
    llave_cliente = derivar_llave_aes(
        secreto_cliente,
        salt
    )

    llave_mitm_cli = derivar_llave_aes(
        secreto_mitm_cli,
        salt
    )

    llave_mitm_srv = derivar_llave_aes(
        secreto_mitm_srv,
        salt
    )

    llave_servidor = derivar_llave_aes(
        secreto_servidor,
        salt
    )

    mensaje = "Transferir 1000 colones"

    cifrado = cifrar_mensaje(llave_cliente, mensaje)

    # El atacante descifra con su llave.
    leido = descifrar_mensaje(llave_mitm_cli, cifrado)

    print(f"[4] Mensaje que lee el atacante: {leido}")

    assert leido == mensaje

    # El atacante lo reenvia al servidor con
    # la llave que comparte con el.
    reenviado = cifrar_mensaje(
        llave_mitm_srv,
        leido
    )

    recibido = descifrar_mensaje(
        llave_servidor,
        reenviado
    )

    print(
        "[5] El servidor recibe el mensaje "
        "reenviado:",
        recibido
    )

    assert recibido == mensaje

    print(
        "[OK] Sin firmas, el atacante leyo y "
        "reenvio el mensaje completo.\n"
    )

    # ==========================================
    # PARTE 2: PROTOCOLO CON FIRMAS
    # El atacante sustituye una llave, pero no
    # puede firmar con la identidad real.
    # ==========================================

    print("--- Parte 2: protocolo CON firmas ---")

    # Transcripcion firmada por el servidor real
    # con su llave X25519 autentica.
    firma_legitima = firmar_intercambio(
        "servidor",
        publica_servidor,
        publica_cliente,
        salt
    )

    # El cliente verifica contra la llave que
    # el atacante le presento (publica_a).
    resultado_falso = verificar_intercambio(
        "servidor",
        publica_a,
        publica_cliente,
        salt,
        firma_legitima
    )

    print(
        "[6] Firma real aceptada con llave "
        "sustituida:",
        resultado_falso
    )

    assert resultado_falso is False

    # El atacante intenta firmar con su propia
    # llave Ed25519 (no es la identidad real).
    atacante = Ed25519PrivateKey.generate()

    transcripcion = construir_transcripcion(
        publica_a,
        publica_cliente,
        salt
    )

    datos = b"servidor" + transcripcion

    firma_atacante = atacante.sign(datos)

    resultado_atacante = verificar_intercambio(
        "servidor",
        publica_a,
        publica_cliente,
        salt,
        firma_atacante
    )

    print(
        "[7] Firma del atacante aceptada:",
        resultado_atacante
    )

    assert resultado_atacante is False

    # La firma legitima sobre la transcripcion
    # correcta sigue siendo valida.
    resultado_legitimo = verificar_intercambio(
        "servidor",
        publica_servidor,
        publica_cliente,
        salt,
        firma_legitima
    )

    print(
        "[8] Firma legitima en transcripcion "
        "correcta:",
        resultado_legitimo
    )

    assert resultado_legitimo is True

    print(
        "\n[OK] Todas las pruebas MITM fueron "
        "exitosas."
    )
    print(
        "[SEGURIDAD] Sin firmas el ataque funciona; "
        "con firmas Ed25519 es bloqueado."
    )

    print("\n=== PRUEBA FINALIZADA ===")


if __name__ == "__main__":
    main()
