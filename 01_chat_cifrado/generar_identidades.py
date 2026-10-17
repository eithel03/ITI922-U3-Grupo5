#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Grupo 5 - Seguridad de TI II

Generacion de identidades Ed25519.

Genera:
- Llave privada del servidor.
- Llave publica del servidor.
- Llave privada del cliente.
- Llave publica del cliente.

Las llaves privadas no deben compartirse.
"""

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption
)


DIRECTORIO = Path(__file__).resolve().parent / "identidades"


def generar_identidad(nombre):

    privada = Ed25519PrivateKey.generate()

    publica = privada.public_key()

    privada_bytes = privada.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption()
    )

    publica_bytes = publica.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw
    )

    archivo_privado = DIRECTORIO / f"{nombre}_privada.key"
    archivo_publico = DIRECTORIO / f"{nombre}_publica.key"

    # Evitar sobrescribir identidades existentes.
    for archivo in (archivo_privado, archivo_publico):
        if archivo.exists():
            raise FileExistsError(
                f"Ya existe {archivo}. No se reemplazara."
            )

    # Crear llave privada con permisos restrictivos.
    with archivo_privado.open("xb") as archivo:
        archivo.write(privada_bytes)

    archivo_privado.chmod(0o600)

    with archivo_publico.open("xb") as archivo:
        archivo.write(publica_bytes)

    archivo_publico.chmod(0o644)

    print(f"[OK] Identidad {nombre} generada.")


def main():

    print("=== GENERACION DE IDENTIDADES ED25519 ===")

    DIRECTORIO.mkdir(
        parents=True,
        exist_ok=True
    )

    generar_identidad("servidor")
    generar_identidad("cliente")

    print("\n[OK] Identidades generadas correctamente.")
    print("[SEGURIDAD] No compartir las llaves privadas.")


if __name__ == "__main__":
    main()
