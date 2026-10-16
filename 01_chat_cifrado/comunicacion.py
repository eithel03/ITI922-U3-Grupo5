import struct


def recibir_exacto(conexion, cantidad):
    datos = b""

    while len(datos) < cantidad:
        bloque = conexion.recv(cantidad - len(datos))

        if not bloque:
            raise ConnectionError("Conexion cerrada")

        datos += bloque

    return datos


def enviar_datos(conexion, datos):
    # Enviar primero la longitud del mensaje.
    longitud = struct.pack("!I", len(datos))

    # Enviar longitud y contenido.
    conexion.sendall(longitud + datos)


def recibir_datos(conexion):
    # Leer los primeros 4 bytes.
    encabezado = recibir_exacto(conexion, 4)

    # Obtener la longitud.
    longitud = struct.unpack("!I", encabezado)[0]

    # Limitar el tamaño aceptado.
    if longitud > 1048576:
        raise ValueError("Mensaje demasiado grande")

    return recibir_exacto(conexion, longitud)
