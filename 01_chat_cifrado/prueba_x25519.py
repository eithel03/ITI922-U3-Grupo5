#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from criptografia import (
    generar_llaves,
    calcular_secreto,
    derivar_llave_aes,
    generar_salt
)


def main():

    print("=== PRUEBA X25519 + HKDF ===\n")

    # Simular a los dos participantes.
    privada_cliente, publica_cliente = generar_llaves()
    privada_servidor, publica_servidor = generar_llaves()

    print("[1] Llaves X25519 generadas correctamente.")

    # Cada participante utiliza la llave publica del otro.
    secreto_cliente = calcular_secreto(
        privada_cliente,
        publica_servidor
    )

    secreto_servidor = calcular_secreto(
        privada_servidor,
        publica_cliente
    )

    print("[2] Secretos compartidos calculados.")

    # Verificar que ambos secretos coincidan.
    print(
        "[3] Secretos iguales:",
        secreto_cliente == secreto_servidor
    )

    # Generar un salt compartido.
    salt = generar_salt()

    # Derivar la llave AES desde cada participante.
    aes_cliente = derivar_llave_aes(
        secreto_cliente,
        salt
    )

    aes_servidor = derivar_llave_aes(
        secreto_servidor,
        salt
    )

    print("[4] Llaves AES derivadas mediante HKDF.")

    print(
        "[5] Llaves AES iguales:",
        aes_cliente == aes_servidor
    )

    print(
        "[6] Tamano de la llave AES:",
        len(aes_cliente) * 8,
        "bits"
    )


if __name__ == "__main__":
    main()
