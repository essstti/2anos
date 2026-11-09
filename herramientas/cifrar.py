"""
Cifra la carta y la contraseña de entrada y las pone en index.html.

La carta y las contraseñas NO se guardan en el repo: solo se guarda la versión cifrada.

Uso (desde la carpeta del proyecto):
    pip install cryptography
    python herramientas/cifrar.py carta.json CONTRASEÑA_ENTRADA CONTRASEÑA_CARTA

carta.json tiene esta forma (y NO se sube a GitHub: está en .gitignore):
    {"parrafos": ["Primer párrafo...", "Segundo párrafo..."], "firma": "Esteban."}

El símbolo ♡ dentro de un párrafo se muestra grande y en rojo.
"""
import base64
import json
import os
import re
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITERACIONES = 200000


def cifrar(texto, clave):
    sal, iv = os.urandom(16), os.urandom(12)
    # igual que en la página: no importan mayúsculas ni espacios al principio o al final
    llave = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=sal,
                       iterations=ITERACIONES).derive(clave.strip().lower().encode())
    datos = AESGCM(llave).encrypt(iv, texto.encode('utf-8'), None)
    b64 = lambda x: base64.b64encode(x).decode()
    return {'sal': b64(sal), 'iv': b64(iv), 'it': ITERACIONES, 'datos': b64(datos)}


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(1)
    ruta_carta, clave_entrada, clave_carta = sys.argv[1:]
    carta = json.load(open(ruta_carta, encoding='utf-8'))
    assert isinstance(carta.get('parrafos'), list) and 'firma' in carta, 'carta.json no tiene la forma esperada'

    html = open('index.html', encoding='utf-8').read()
    nuevo_entrada = json.dumps(cifrar('ok', clave_entrada))
    nuevo_carta = json.dumps(cifrar(json.dumps(carta, ensure_ascii=False), clave_carta))
    html, n1 = re.subn(r'const SECRETO_ENTRADA = \{[^\n]*\};', lambda m: f'const SECRETO_ENTRADA = {nuevo_entrada};', html)
    html, n2 = re.subn(r'const CARTA_CIFRADA = \{[^\n]*\};', lambda m: f'const CARTA_CIFRADA = {nuevo_carta};', html)
    assert n1 == 1 and n2 == 1, 'no encontré dónde poner los datos cifrados en index.html'
    open('index.html', 'w', encoding='utf-8').write(html)
    print('Listo: carta y contraseña de entrada cifradas en index.html')


if __name__ == '__main__':
    main()
