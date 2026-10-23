
import socket
import threading
import os

from cryptography.hazmat.primitives.asymmetric import rsa, x25519, mlkem, padding
from cryptography.hazmat.primitives import serialization, hashes


HOST = "127.0.0.1"


def recibir(sock, cantidad):
    datos = b""
    while len(datos) < cantidad:
        bloque = sock.recv(cantidad - len(datos))
        if not bloque:
            raise ConnectionError("La conexión se cerró antes de recibir todos los datos")
        datos += bloque
    return datos


def clave_der(clave):
    return clave.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def servidor_rsa(sock):
    privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    publica_bytes = clave_der(privada.public_key())

    sock.sendall(publica_bytes)
    cifrado = recibir(sock, 384)

    secreto = privada.decrypt(
        cifrado,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    assert len(secreto) == 32


def cliente_rsa(sock):
    publica_bytes = recibir(sock, 422)
    publica = serialization.load_der_public_key(publica_bytes)
    secreto = os.urandom(32)

    cifrado = publica.encrypt(
        secreto,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    sock.sendall(cifrado)


def servidor_x25519(sock):
    publica_cliente = x25519.X25519PublicKey.from_public_bytes(
        recibir(sock, 32)
    )
    privada = x25519.X25519PrivateKey.generate()
    sock.sendall(privada.public_key().public_bytes_raw())

    secreto = privada.exchange(publica_cliente)
    assert len(secreto) == 32


def cliente_x25519(sock):
    privada = x25519.X25519PrivateKey.generate()
    sock.sendall(privada.public_key().public_bytes_raw())

    publica_servidor = x25519.X25519PublicKey.from_public_bytes(
        recibir(sock, 32)
    )
    secreto = privada.exchange(publica_servidor)
    assert len(secreto) == 32


def servidor_mlkem(sock):
    bytes_publica = recibir(sock, 1184)
    publica = mlkem.MLKEM768PublicKey.from_public_bytes(bytes_publica)

    secreto, cifrado = publica.encapsulate()
    sock.sendall(cifrado)
    assert len(secreto) == 32


def cliente_mlkem(sock):
    privada = mlkem.MLKEM768PrivateKey.generate()
    sock.sendall(privada.public_key().public_bytes_raw())

    cifrado = recibir(sock, 1088)
    secreto = privada.decapsulate(cifrado)
    assert len(secreto) == 32


def ejecutar(nombre, puerto, funcion_servidor, funcion_cliente):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((HOST, puerto))
    listener.listen(1)

    errores = []

    def atender():
        try:
            conexion, _ = listener.accept()
            with conexion:
                funcion_servidor(conexion)
        except Exception as error:
            errores.append(error)
        finally:
            listener.close()

    hilo = threading.Thread(target=atender)
    hilo.start()

    try:
        with socket.create_connection((HOST, puerto), timeout=10) as cliente:
            cliente.settimeout(10)
            funcion_cliente(cliente)
    except Exception:
        hilo.join()
        raise

    hilo.join()

    if errores:
        raise errores[0]

    print(f"{nombre}: intercambio TCP completado en puerto {puerto}")


def main():
    ejecutar("RSA-3072", 5101, servidor_rsa, cliente_rsa)
    ejecutar("X25519", 5102, servidor_x25519, cliente_x25519)
    ejecutar("ML-KEM-768", 5103, servidor_mlkem, cliente_mlkem)
    print("Los tres intercambios terminaron correctamente.")


if __name__ == "__main__":
    main()
