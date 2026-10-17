#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Proyecto: Algoritmos asimetricos y post-cuanticos
Curso: ITI-922 Seguridad de TI II
Grupo: 5

Prueba de firmas digitales Ed25519.

Se comprueba:
1. Generacion de llaves.
2. Firma digital valida.
3. Rechazo de mensaje modificado.
4. Rechazo de firma incorrecta.
"""

from criptografia import (
    generar_llaves_ed25519,
    firmar_mensaje,
    verificar_firma
)


def main():

    print("=== PRUEBA DE FIRMAS ED25519 ===\n")

    # ------------------------------------------
    # 1. GENERAR LLAVES
    # ------------------------------------------

    privada, publica = generar_llaves_ed25519()

    print("[1] Llaves Ed25519 generadas correctamente.")

    # ------------------------------------------
    # 2. CREAR MENSAJE
    # ------------------------------------------

    mensaje = b"Hola servidor, mensaje del Grupo 5"

    print("[2] Mensaje original:", mensaje.decode())

    # ------------------------------------------
    # 3. FIRMAR MENSAJE
    # ------------------------------------------

    firma = firmar_mensaje(
        privada,
        mensaje
    )

    print("[3] Firma digital generada.")
    print("[4] Tamano de firma:", len(firma), "bytes")

    # ------------------------------------------
    # 4. VERIFICAR FIRMA VALIDA
    # ------------------------------------------

    resultado = verificar_firma(
        publica,
        mensaje,
        firma
    )

    print("[5] Firma valida:", resultado)

    assert resultado is True, "La firma valida fue rechazada"

    # ------------------------------------------
    # 5. MODIFICAR MENSAJE
    # ------------------------------------------

    mensaje_modificado = (
        b"Hola servidor, mensaje MODIFICADO"
    )

    resultado_modificado = verificar_firma(
        publica,
        mensaje_modificado,
        firma
    )

    print(
        "[6] Firma de mensaje modificado:",
        resultado_modificado
    )

    assert resultado_modificado is False, (
        "No se detecto la modificacion del mensaje"
    )

    # ------------------------------------------
    # 6. PROBAR FIRMA INCORRECTA
    # ------------------------------------------

    firma_incorrecta = bytearray(firma)

    # Modificar un byte de la firma.
    firma_incorrecta[0] ^= 1

    resultado_incorrecto = verificar_firma(
        publica,
        mensaje,
        bytes(firma_incorrecta)
    )

    print(
        "[7] Firma incorrecta aceptada:",
        resultado_incorrecto
    )

    assert resultado_incorrecto is False, (
        "La firma incorrecta fue aceptada"
    )

    print("\n[OK] Todas las pruebas Ed25519 fueron exitosas.")

    print("\n=== PRUEBA FINALIZADA ===")


if __name__ == "__main__":
    main()
