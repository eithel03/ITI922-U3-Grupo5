#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket

HOST = "127.0.0.1"
PUERTO = 5000


def main():

    # Crear socket TCP
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Permitir reutilizar el puerto
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Asociar el servidor con una IP y puerto
    servidor.bind((HOST, PUERTO))

    # Esperar una conexion
    servidor.listen(1)

    print("[SERVIDOR] Esperando conexion...")
    print(f"[SERVIDOR] Escuchando en {HOST}:{PUERTO}")

    conexion, direccion = servidor.accept()

    print(f"[SERVIDOR] Cliente conectado desde {direccion}")

    try:
        while True:

            # Recibir mensaje del cliente
            datos = conexion.recv(4096)

            if not datos:
                print("[SERVIDOR] Cliente desconectado.")
                break

            mensaje = datos.decode("utf-8")

            print(f"\n[CLIENTE]: {mensaje}")

            if mensaje.lower() == "salir":
                break

            # Responder al cliente
            respuesta = input("[SERVIDOR]: ")

            conexion.sendall(respuesta.encode("utf-8"))

            if respuesta.lower() == "salir":
                break

    except KeyboardInterrupt:
        print("\n[SERVIDOR] Interrumpido por el usuario.")

    finally:
        conexion.close()
        servidor.close()

        print("[SERVIDOR] Conexion cerrada.")


if __name__ == "__main__":
    main()
