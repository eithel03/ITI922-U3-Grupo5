import csv
import statistics
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa, x25519, mlkem
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

CARPETA = Path(__file__).parent
ITERACIONES = 10


def medir(funcion):
    inicio = time.perf_counter_ns()
    resultado = funcion()
    fin = time.perf_counter_ns()
    milisegundos = (fin - inicio) / 1_000_000
    return resultado, milisegundos


def clave_der(clave):
    return clave.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def ejecutar_rsa():
    privada, tiempo_generacion = medir(
        lambda: rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,
        )
    )

    publica = privada.public_key()
    bytes_publica = clave_der(publica)
    secreto_original = b"S" * 32

    cifrado, tiempo_operacion = medir(
        lambda: publica.encrypt(
            secreto_original,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    )

    recuperado = privada.decrypt(
        cifrado,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    assert recuperado == secreto_original

    return {
        "algoritmo": "RSA-3072",
        "formato_clave": "DER/SPKI",
        "bytes_clave_publica": len(bytes_publica),
        "bytes_intercambio": len(bytes_publica) + len(cifrado),
        "tiempo_generacion_ms": tiempo_generacion,
        "tiempo_operacion_ms": tiempo_operacion,
    }


def ejecutar_x25519():
    privada_a, tiempo_generacion = medir(
        x25519.X25519PrivateKey.generate
    )
    privada_b = x25519.X25519PrivateKey.generate()

    publica_a = privada_a.public_key().public_bytes_raw()
    publica_b = privada_b.public_key().public_bytes_raw()

    secreto_a, tiempo_operacion = medir(
        lambda: privada_a.exchange(privada_b.public_key())
    )
    secreto_b = privada_b.exchange(privada_a.public_key())

    assert secreto_a == secreto_b

    return {
        "algoritmo": "X25519",
        "formato_clave": "Raw",
        "bytes_clave_publica": len(publica_a),
        "bytes_intercambio": len(publica_a) + len(publica_b),
        "tiempo_generacion_ms": tiempo_generacion,
        "tiempo_operacion_ms": tiempo_operacion,
    }


def ejecutar_mlkem():
    privada, tiempo_generacion = medir(
        mlkem.MLKEM768PrivateKey.generate
    )
    publica = privada.public_key()
    bytes_publica = publica.public_bytes_raw()

    (secreto_a, cifrado), tiempo_operacion = medir(
        publica.encapsulate
    )
    secreto_b = privada.decapsulate(cifrado)

    assert secreto_a == secreto_b

    return {
        "algoritmo": "ML-KEM-768",
        "formato_clave": "Raw",
        "bytes_clave_publica": len(bytes_publica),
        "bytes_intercambio": len(bytes_publica) + len(cifrado),
        "tiempo_generacion_ms": tiempo_generacion,
        "tiempo_operacion_ms": tiempo_operacion,
    }



def crear_grafico(nombre, titulo, etiquetas, valores, eje_y):
    ancho = 900
    alto = 480
    izquierda = 100
    derecha = 35
    arriba = 75
    abajo = 100

    area_ancho = ancho - izquierda - derecha
    area_alto = alto - arriba - abajo
    maximo = max(valores) * 1.15 if max(valores) > 0 else 1
    espacio = area_ancho / len(valores)
    ancho_barra = min(100, espacio * 0.55)

    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'width="{ancho}" height="{alto}" viewBox="0 0 {ancho} {alto}">',
        '<rect width="100%" height="100%" fill="white"/>',
        f'<text x="{ancho / 2}" y="35" text-anchor="middle" '
        f'font-family="Arial" font-size="22" font-weight="bold">'
        f'{titulo}</text>',
        f'<text x="25" y="{alto / 2}" '
        f'transform="rotate(-90 25 {alto / 2})" '
        f'text-anchor="middle" font-family="Arial" font-size="14">'
        f'{eje_y}</text>',
    ]

    for i in range(5):
        y = arriba + area_alto - area_alto * i / 4
        valor = maximo * i / 4

        svg.append(
            f'<line x1="{izquierda}" y1="{y}" '
            f'x2="{ancho - derecha}" y2="{y}" '
            f'stroke="#dddddd"/>'
        )
        svg.append(
            f'<text x="{izquierda - 12}" y="{y + 5}" '
            f'text-anchor="end" font-family="Arial" font-size="12">'
            f'{valor:.1f}</text>'
        )

    for i, (etiqueta, valor) in enumerate(zip(etiquetas, valores)):
        x = izquierda + espacio * i + (espacio - ancho_barra) / 2
        altura_barra = area_alto * valor / maximo
        y = arriba + area_alto - altura_barra

        svg.append(
            f'<rect x="{x}" y="{y}" width="{ancho_barra}" '
            f'height="{altura_barra}" fill="#3978b8"/>'
        )
        svg.append(
            f'<text x="{x + ancho_barra / 2}" y="{y - 8}" '
            f'text-anchor="middle" font-family="Arial" font-size="13">'
            f'{valor:.2f}</text>'
        )
        svg.append(
            f'<text x="{x + ancho_barra / 2}" y="{alto - abajo + 25}" '
            f'text-anchor="middle" font-family="Arial" font-size="13">'
            f'{etiqueta}</text>'
        )

    svg.append("</svg>")
    (CARPETA / nombre).write_text("\n".join(svg), encoding="utf-8")


def main():
    algoritmos = [ejecutar_rsa, ejecutar_x25519, ejecutar_mlkem]
    resultados = []

    print(f"Ejecutando {ITERACIONES} mediciones por algoritmo...\n")

    for funcion in algoritmos:
        muestras = [funcion() for _ in range(ITERACIONES)]
        primera = muestras[0]

        resultado = {
            "algoritmo": primera["algoritmo"],
            "formato_clave": primera["formato_clave"],
            "bytes_clave_publica": primera["bytes_clave_publica"],
            "bytes_intercambio": primera["bytes_intercambio"],
            "tiempo_generacion_ms": statistics.mean(
                m["tiempo_generacion_ms"] for m in muestras
            ),
            "tiempo_operacion_ms": statistics.mean(
                m["tiempo_operacion_ms"] for m in muestras
            ),
        }

        resultados.append(resultado)
        print(f"Mediciones de {resultado['algoritmo']} completadas.")

    campos = list(resultados[0].keys())

    with (CARPETA / "resultados.csv").open(
        "w", newline="", encoding="utf-8"
    ) as archivo:
        escritor = csv.DictWriter(archivo, fieldnames=campos)
        escritor.writeheader()
        escritor.writerows(resultados)

    lineas = [
        "# Comparación de algoritmos criptográficos",
        "",
        f"Promedio de {ITERACIONES} ejecuciones por algoritmo.",
        "",
        "| Algoritmo | Formato de clave pública | Clave pública (bytes) | Bytes del intercambio modelado | Generación de claves (ms) | Operación principal (ms) |",
        "|---|---|---:|---:|---:|---:|",
    ]

    for r in resultados:
        lineas.append(
            f"| {r['algoritmo']} | {r['formato_clave']} | "
            f"{r['bytes_clave_publica']} | {r['bytes_intercambio']} | "
            f"{r['tiempo_generacion_ms']:.4f} | "
            f"{r['tiempo_operacion_ms']:.4f} |"
        )

    lineas.extend([
        "",
        "## Interpretación de los datos",
        "",
        "- RSA-3072: se cuentan la clave pública en DER/SPKI y el cifrado RSA-OAEP de un secreto de 32 bytes.",
        "- X25519: se cuentan las dos claves públicas raw intercambiadas para calcular un secreto compartido.",
        "- ML-KEM-768: se cuentan la clave pública raw y el texto cifrado de encapsulación.",
        "",
        "Los bytes calculados corresponden a mensajes criptográficos modelados; no incluyen cabeceras TCP/IP, TLS ni metadatos de red.",
        "",
        "La captura de Wireshark se realizará por separado para observar el tráfico real.",
        "",
        "Los tiempos de operación no son totalmente equivalentes: RSA cifra un secreto, X25519 calcula un secreto compartido y ML-KEM encapsula un secreto.",
        "",
        "Los resultados pueden variar según el equipo y la carga del sistema.",
    ])

    (CARPETA / "resultados.md").write_text(
        "\n".join(lineas), encoding="utf-8"
    )

    etiquetas = [r["algoritmo"] for r in resultados]

    crear_grafico(
        "grafico_tamanos.svg",
        "Tamaño estimado del intercambio criptográfico",
        etiquetas,
        [r["bytes_intercambio"] for r in resultados],
        "Bytes",
    )

    crear_grafico(
        "grafico_tiempos.svg",
        "Tiempo promedio de generación de claves",
        etiquetas,
        [r["tiempo_generacion_ms"] for r in resultados],
        "Milisegundos",
    )

    print("\nArchivos generados:")
    print(" - resultados.csv")
    print(" - resultados.md")
    print(" - grafico_tamanos.svg")
    print(" - grafico_tiempos.svg")

    print("\n" + (CARPETA / "resultados.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
