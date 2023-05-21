import socket

def is_onion_valid(domain):
    try:
        onion_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        onion_socket.connect((domain + ".onion", 80))
        onion_socket.close()
        return True
    except ConnectionRefusedError:
        return False
    except Exception:
        return False

enlace = input("Ingrese el enlace: ").strip()

if enlace.endswith(".onion/"):
    dominio = enlace.split(".onion/")[0]
    if is_onion_valid(dominio):
        print(f"El dominio {dominio}.onion es un enlace válido en la dark web.")
    else:
        print(f"El dominio {dominio}.onion no es un enlace válido en la dark web.")
else:
    print(f"El enlace {enlace} no es un enlace .onion válido.")
