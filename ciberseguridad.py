from flask import Flask, render_template, request
import requests
import re
from bs4 import BeautifulSoup
import ssl
import json
import socket
import whois
import smtplib


def website_information():
    url = input("Ingrese la URL del sitio web a analizar: ")
    
    response = requests.get(url)
    
    if response.status_code == 200:
        # Realiza el análisis de la página web y extrae la información relevante
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extrae el título de la página
        title = soup.title.string
        
        # Extrae los enlaces de la página
        links = [link.get('href') for link in soup.find_all('a')]
        
        # Extrae los encabezados de la página
        headers = [header.text for header in soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])]
        
        # Verifica si la página web utiliza el protocolo HTTPS
        is_https = url.startswith('https')
        
        # Verifica si la página web tiene un certificado SSL válido
        has_valid_ssl = False
        if is_https:
            hostname = url.split('/')[2]
            try:
                ssl.create_default_context().check_hostname = False
                ssl.SSLContext().verify_mode = ssl.CERT_NONE
                ssl.get_server_certificate((hostname, 443))
                has_valid_ssl = True
            except:
                has_valid_ssl = False
        
        # Muestra la información obtenida
        print("Información del sitio web", url)
        print("Título:", title)
        print("Enlaces:", links)
        print("Encabezados:", headers)
        if is_https and has_valid_ssl:
            print("¿Es segura?: Sí")
            print("Protocolos de seguridad: HTTPS, Certificado SSL válido")
        else:
            print("¿Es segura?: No")
            if not is_https:
                print("Protocolos de seguridad faltantes: HTTPS")
            if not has_valid_ssl:
                print("Protocolos de seguridad faltantes: Certificado SSL válido")
    else:
        print("No se pudo acceder al sitio web. Verifique la URL e intente nuevamente.")


#segunda funcion

def phone_number_information():

        url = "https://api.apilayer.com/number_verification/validate?number="

        numero = input("Ingrese el número de teléfono (con código de país): ")

        url += numero

        payload = {}
        headers = {
          "apikey": "D25NAi6frOY6wijqC638Tni4Iv1HxRP4"
        }

        response = requests.request("GET", url, headers=headers, data=payload)

        status_code = response.status_code
        result = response.text


        print("Código de estado:", status_code)
        print("Resultado:", result)


#tercera funcion
def subdomain_scanner():
    dominio = input("Ingrese el dominio a escanear: ")
    
    # Realiza una búsqueda de DNS para obtener la dirección IP del dominio
    direccion_ip = socket.gethostbyname(dominio)
    
    # Obtiene el certificado SSL del dominio (si está disponible)
    certificado_ssl = None
    try:
        contexto = ssl.create_default_context()
        with socket.create_connection((dominio, 443)) as sock:
            with contexto.wrap_socket(sock, server_hostname=dominio) as ssock:
                certificado_ssl = ssock.getpeercert()
    except:
        pass
    
    # Muestra la información obtenida
    print("Información del dominio", dominio)
    print("Dirección IP:", direccion_ip)
    if certificado_ssl:
        print("Certificado SSL: Disponible")
        # Obtener información adicional del certificado SSL
        print("Emisor del certificado:", certificado_ssl['issuer'][0][0][1])
        print("Sujeto del certificado:", certificado_ssl['subject'][0][0][1])
        print("Fecha de vencimiento del certificado:", certificado_ssl['notAfter'])
    else:
        print("Certificado SSL: No disponible")


#cuarta funcion

def analyze_accounts():
    
   # Analiza una cuenta de correo electrónico utilizando la API de Validación de Correo Electrónico de Abstract.
  
    email = input("Ingrese la dirección de correo electrónico para analizar: ")
    
    # Clave de API para acceder a la API de Validación de Correo Electrónico de Abstract
    api_key = "4ef36f0c74c64c9780608494573effc6"
    
    # Construye la URL de la API con el correo electrónico y la clave de API
    url = f"https://emailvalidation.abstractapi.com/v1/?api_key={api_key}&email={email}"
    
    # Envía una solicitud GET a la API
    response = requests.get(url)
    
    # Imprime el código de estado de la respuesta
    print("Código de estado:", response.status_code)
    
    # Imprime el contenido de respuesta del servidor
    print("Respuesta del servidor:")
    print(response.content)



def is_dark_web(url):
    pattern = r'\.onion$'
    if re.search(pattern, url):
        return True
    else:
        return False

def analyze_vulnerability():
    url = input("Ingrese la URL del sitio web a analizar: ")
    
    # Se determina si la página puede estar en la dark web
    if is_dark_web(url):
        print(f"{url} está en la dark web.")
       
        key = Fernet.generate_key()
        cipher = Fernet(key)
        encrypted_messages = []

        for _ in range(50):
           
            message_length = random.randint(10, 20)
            message = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(message_length))

            # Encripta el mensaje
            encrypted_message = cipher.encrypt(message.encode())
            encrypted_messages.append(encrypted_message)

        # Imprime los mensajes encriptados
        print("Mensajes encriptados:")
        for encrypted_message in encrypted_messages:
            print("-", encrypted_message)
    else:
        print(f"{url} no está en la dark web.")

    
    try:
        response = requests.get(url, verify=True)
        
        # Realiza el análisis de la página web y extrae la información relevante
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Verifica si la página web utiliza el protocolo HTTPS
        is_https = url.startswith('https')
        
        # Detecta posibles problemas de seguridad y datos vulnerables
        security_issues = []
        vulnerable_data = []
        
        if not is_https:
            security_issues.append("La página no utiliza HTTPS, lo que puede permitir ataques de intermediarios y robo de datos.")
        else:
            security_issues.append("La página utiliza el protocolo HTTPS, lo que la hace segura y efectiva.")
        
        # Verifica si hay formularios que envíen información sin cifrar
        insecure_forms = soup.find_all('form', action=lambda x: x and not x.startswith('https'))
        if insecure_forms:
            security_issues.append(f"Se encontraron {len(insecure_forms)} formularios que envían información sin cifrar.")
        
        # Verifica si hay enlaces a páginas no seguras
        insecure_links = soup.find_all('a', href=lambda x: x and not x.startswith('https'))
        if insecure_links:
            security_issues.append(f"Se encontraron {len(insecure_links)} enlaces a páginas no seguras.")
        
        # Verifica si hay contenido sospechoso en la página
        suspicious_content = soup.find_all(text=re.compile(r'(?i)hack|phish|scam|malware|virus'))
        if suspicious_content:
            security_issues.append(f"Se encontró contenido sospechoso en la página: {', '.join(suspicious_content)}")
        
        # Muestra la información obtenida
        print("Información del sitio web:", url)
        print("---")
        
        # Imprime el título de la página
        title = soup.find('title')
        if title:
            print("Título de la página:", title.text)
        
        # Imprime los metadatos de la página
        metadata = soup.find_all('meta')
        if metadata:
            print("Metadatos:")
            for meta in metadata:
                name = meta.get('name')
                content = meta.get('content')
                if name and content:
                    print(f"- {name}: {content}")
        
        # Imprime las URLs y enlaces de la página
        links = soup.find_all('a', href=True)
        if links:
            print("URLs y enlaces:")
            for link in links:
                href = link['href']
                text = link.text.strip()
                print(f"- {text}: {href}")
        
        # Imprime el texto del contenido de la página
        text_elements = soup.find_all(text=True)
        visible_text = filter(lambda x: x.parent.name not in ['style', 'script', 'head', 'title', 'meta'], text_elements)
        visible_text = [t.strip() for t in visible_text if t.strip()]
        if visible_text:
            print("Texto del contenido:")
            for text in visible_text:
                print("-", text)
        
        # Imprime información sobre las imágenes de la página
        images = soup.find_all('img')
        if images:
            print("Imágenes:")
            for image in images:
                src = image.get('src')
                alt = image.get('alt')
                width = image.get('width')
                height = image.get('height')
                print(f"- URL: {src}, Alt: {alt}, Tamaño: {width}x{height}")
                # Imprime la dirección IP de la página web
        hostname = url.split('/')[2]
        ip_address = socket.gethostbyname(hostname)
        print("Dirección IP:", ip_address)

        print("---")
        print("Estado de seguridad:")
        if security_issues:
            for issue in security_issues:
                print("-", issue)
        else:
            print("- No se encontraron problemas de seguridad identificados.")
        
        print("---")
        print("Datos potencialmente vulnerables:")
        if vulnerable_data:
            for data in vulnerable_data:
                print("-", data)
        else:
            print("- No se encontraron datos vulnerables identificados.")
    
    except requests.exceptions.RequestException as e:
        print("No se pudo acceder al sitio web. Verifique la URL e intente nuevamente.")
        print("Error:", str(e))


# Función principal del programa, pequeño menu para demostrar y automatizar las funciones
def main():
    while True:
        print("---- MENÚ ----")
        print("1. Carding")
        print("2. Accounts")
        print("3. Vulnerability")
        print("4. Salir")
        
        option = input("Seleccione una opción: ")
        
        if option == "1":
            print("---- CARDING ----")
            print("1. Información de sitio web")
            print("2. Información de número de teléfono")
            print("3. Escáner de subdominio")
            print("4. Verificación de dirección de correo electrónico")
            
            carding_option = input("Seleccione una opción: ")
            
            if carding_option == "1":
                website_information()
            elif carding_option == "2":
                phone_number_information()
            elif carding_option == "3":
                subdomain_scanner()
          
            else:
                print("Opción inválida. Intente de nuevo.")
        
        elif option == "2":
            analyze_accounts()
        
        elif option == "3":
            analyze_vulnerability()
        
        elif option == "4":
            print("¡Hasta luego!")
            break
        
        else:
            print("Opción inválida. Intente de nuevo.")

# Llamada a la función principal del programa
main()
