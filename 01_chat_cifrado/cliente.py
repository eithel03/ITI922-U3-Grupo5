#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket

HOST = "127.0.0.1"
PUERTO = 5000


def main():

    # Crear socket TCP
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:

        # Conectarse al servidor
        cliente.connect((HOST, PUERTO))

        print("[CLIENTE] Conexion establecida con el servidor.")
        print("[CLIENTE] Escriba 'salir' para finalizar.")

        while True:

            # Escribir mensaje
            mensaje = input("\n[CLIENTE]: ")

            # Enviar mensaje
            cliente.sendall(mensaje.encode("utf-8"))

            if mensaje.lower() == "salir":
                break

            # Recibir respuesta
            datos = cliente.recv(4096)

            if not datos:
                print("[CLIENTE] Servidor desconectado.")
                break

            respuesta = datos.decode("utf-8")

            print(f"[SERVIDOR]: {respuesta}")

            if respuesta.lower() == "salir":
                break

    except ConnectionRefusedError:
        print("[ERROR] No se pudo conectar con el servidor.")

    except KeyboardInterrupt:
        print("\n[CLIENTE] Interrumpido por el usuario.")

    finally:
        cliente.close()

        print("[CLIENTE] Conexion cerrada.")


if __name__ == "__main__":
    main()
