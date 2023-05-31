from flask import Flask, render_template, request
import requests
import tldextract
from bs4 import BeautifulSoup
import ssl
import re
import json
import socket
import string
import socket
import random
from cryptography.fernet import Fernet


app = Flask(__name__)
app.template_folder = './templates'  # Ruta a la carpeta que contiene los archivos HTML

def is_trustworthy(url):
    try:
        domain = tldextract.extract(url).registered_domain
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return True
        else:
            return False
    except:
        return False

def has_malware(content):
    soup = BeautifulSoup(content, 'html.parser')
    # Verificar si la página web contiene algún indicio de malware
    if "malware" in soup.get_text().lower():
        return True
    else:
        return False

def has_adult_content(content):
    soup = BeautifulSoup(content, 'html.parser')
    # Verificar si la página web contiene algún indicio de contenido para adultos
 
    if "adulto" in soup.get_text().lower():
        return True
    else:
        return False
def check_link(link):
    try:
        response = requests.get(link, timeout=5)
        if link.startswith("https"):
            if has_malware(response.content) or has_adult_content(response.content):
                return "lista negra: el enlace contiene virus, malware o es una página para adultos."
            elif is_trustworthy(response.url):
                domain = tldextract.extract(response.url).registered_domain
                if domain.endswith("xvideos.com"):
                    return "lista negra: el enlace es una página para adultos."
                else:
                    return "lista verde: el enlace está libre de virus y es seguro."
            else:
                return "lista gris: el enlace utiliza acortadores o es sospechoso."
        else:
            return "lista gris: el enlace utiliza acortadores o es sospechoso."
    except:
        return "lista gris: el enlace utiliza acortadores o es sospechoso."

def has_redirect(link):
    try:
        response = requests.get(link, timeout=5, allow_redirects=True)
        return response.url != link
    except:
        return False

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        enlaces = request.form['enlaces']
        enlaces = enlaces.split(",")

        # Crear las listas vacías para cada categoría
        verde = []
        gris = []
        negra = []

        # Verificar cada enlace y agregarlo a la lista correspondiente
        for link in enlaces:
            resultado = check_link(link.strip())
            if resultado == "lista verde: el enlace está libre de virus y es seguro.":
                verde.append(link.strip())
            elif resultado == "lista negra: el enlace contiene virus, malware o es una página para adultos.":
                negra.append(link.strip())
            elif resultado == "lista gris: el enlace utiliza acortadores o es sospechoso.":
                gris.append(link.strip())

        return render_template('index.html', verde=verde, gris=gris, negra=negra, resultado=resultado)

    return render_template('index.html')



@app.route('/website_information', methods=['GET', 'POST'])
def website_information():
    if request.method == 'POST':
        url = request.form['url']
    
        response = requests.get(url)
    
        if response.status_code == 200:
            # Realiza el análisis de la página web y extrae la información relevante
            soup = BeautifulSoup(response.text, 'html.parser')

           
              # Extrae el título de la página
            if soup.title is not None:
                title = soup.title.string
            else:
                title = "Título no encontrado"
        
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
            info = {
                'title': title,
                'links': links,
                'headers': headers,
                'is_secure': is_https and has_valid_ssl
            }
        
            return render_template('website_information.html', info=info)
      
    return render_template('website_information.html')


@app.route('/informacion_numero', methods=['GET', 'POST'])
def phone_number_information():
    if request.method == 'POST':
        url = "https://api.apilayer.com/number_verification/validate"
    
        numero = request.form['numero']
    
        payload = {
            'number': numero,
            'apikey': 'D25NAi6frOY6wijqC638Tni4Iv1HxRP4'
        }
    
        response = requests.get(url, params=payload)
    
        status_code = response.status_code
        result = json.loads(response.text)
        return render_template('informacion_numero.html', status_code=status_code, result=result)
    return render_template('informacion_numero.html')
  

@app.route('/dominio_informacion', methods=['GET', 'POST'])
def dominio_information():
    if request.method == 'POST':
        dominio = request.form['dominio']
        
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
        
        # Prepara la información para pasarla a la plantilla
        informacion = {
            'dominio': dominio,
            'direccion_ip': direccion_ip,
            'certificado_ssl': certificado_ssl
        }
        
        return render_template('dominio_informacion.html', informacion=informacion)
    
    return render_template('dominio_informacion.html')



@app.route('/cuentas', methods=['GET', 'POST'])
def analyze_accounts():
    if request.method == 'POST':
        email = request.form['email']
        
        # Clave de API para acceder a la API de Validación de Correo Electrónico de Abstract
        api_key = "4ef36f0c74c64c9780608494573effc6"
        
        # Construye la URL de la API con el correo electrónico y la clave de API
        url = f"https://emailvalidation.abstractapi.com/v1/?api_key={api_key}&email={email}"
        
        # Envía una solicitud GET a la API
        response = requests.get(url)
        
        # Decodifica la respuesta del JSON con codificación UTF-8
        result = json.loads(response.text.encode('utf-8'))
        
        # Diccionario de traducción inglés-español
        traducciones = {
            'email': 'correo electrónico',
            'status_code': 'Código de estado',
            'result': {
                'autocorrect': 'Autocorrección',
                'deliverability': 'Entregabilidad',
                'quality_score': 'Puntaje de calidad del 0.00 a 1.0',
                'is_valid_format': 'Formato válido',
                'is_free_email': 'Correo electrónico gratuito',
                'is_disposable_email': 'Correo electrónico desechable',
                'is_role_email': 'Correo electrónico de rol',
                'is_catchall_email': 'Correo electrónico catch-all',
                'is_mx_found': 'MX encontrado',
                'is_smtp_valid': 'SMTP válido'
            }
        }
        
        # Función para traducir los resultados al español
        def traducir_resultados(result):
            traducidos = {}
            for clave, valor in result.items():
                if clave in traducciones['result']:
                    clave_traducida = traducciones['result'][clave]
                    traducidos[clave_traducida] = valor
            return traducidos
        
        # Prepara la información para pasarla a la plantilla
        informacion = {
            'email': email,
            'status_code': response.status_code,
            'result': traducir_resultados(result)
        }
        
        return render_template('cuentas.html', informacion=informacion)
    
    return render_template('cuentas.html')




def is_dark_web(url):
    pattern = r'\.onion$'
    if re.search(pattern, url):
        return True
    else:
        return False
@app.route('/dark', methods=['GET', 'POST'])
def analyze_vulnerability():
    if request.method == 'POST':
        url = request.form['url']

        # Se determina si la página puede estar en la dark web
        if is_dark_web(url):
            result = f"{url} está en la dark web."

            key = Fernet.generate_key()
            cipher = Fernet(key)
            encrypted_messages = []

            for _ in range(50):
                message_length = random.randint(10, 20)
                message = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(message_length))

                encrypted_message = cipher.encrypt(message.encode())
                encrypted_messages.append(encrypted_message)

            encrypted_messages = [encrypted_message.decode() for encrypted_message in encrypted_messages]

            return render_template('dark.html', result=result, encrypted_messages=encrypted_messages)
        else:
            result = f"{url} NO está en la dark web."

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
                result = f"Información del sitio web: {url}"
                
                title_info = ""
                title = soup.find('title')
                if title:
                    title_info += f"\nTítulo de la página: {title.text}"

                metadata_info = ""
                metadata_list = []
                metadata = soup.find_all('meta')
                if metadata:
                    metadata_info += "\nMetadatos:"
                    for meta in metadata:
                        name = meta.get('name')
                        content = meta.get('content')
                        if name and content:
                            metadata_list.append(f"{name}: {content}")

                links_info = ""
                links_list = []
                links = soup.find_all('a', href=True)
                if links:
                    links_info += "\nURLs y enlaces:"
                    for link in links:
                        href = link['href']
                        text = link.text.strip()
                        links_list.append(f"{text}: {href}")

                content_text = ""
                content_list = []
                text_elements = soup.find_all(text=True)
                visible_text = filter(lambda x: x.parent.name not in ['style', 'script', 'head', 'title', 'meta'], text_elements)
                visible_text = [t.strip() for t in visible_text if t.strip()]
                if visible_text:
                    content_text += "\nTexto del contenido:"
                    for text in visible_text:
                        content_list.append(text)

                images_info = ""
                images_list = []
                images = soup.find_all('img')
                if images:
                    images_info += "\nImágenes:"
                    for image in images:
                        src = image.get('src')
                        alt = image.get('alt')
                        width = image.get('width')
                        height = image.get('height')
                        images_list.append(f"URL: {src}, Alt: {alt}, Tamaño: {width}x{height}")

                ip_address_info = ""
                hostname = url.split('/')[2]
                ip_address = socket.gethostbyname(hostname)
                ip_address_info += f"\nDirección IP: {ip_address}"

                security_issues_info = "\n\nEstado de seguridad:"
                if security_issues:
                    for issue in security_issues:
                        security_issues_info += f"\n- {issue}"
                else:
                    security_issues_info += "\n- No se encontraron problemas de seguridad identificados."

                vulnerable_data_info = "\n\nDatos potencialmente vulnerables:"
                if vulnerable_data:
                    for data in vulnerable_data:
                        vulnerable_data_info += f"\n- {data}"
                else:
                    vulnerable_data_info += "\n- No se encontraron datos vulnerables identificados."

                return render_template('dark.html', result=result, title=title_info, metadata=metadata_list, links=links_list, content=content_list, images=images_list, ip_address=ip_address_info, security_issues=security_issues_info, vulnerable_data=vulnerable_data_info)
            except requests.exceptions.RequestException as e:
                error = f"No se pudo acceder al sitio web. Verifique la URL e intente nuevamente.\nError: {str(e)}"
                return render_template('dark.html', error=error)

    return render_template('dark.html')






if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)
