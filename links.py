from flask import Flask, render_template, request
import requests
import tldextract
from bs4 import BeautifulSoup
import ssl
import json
import socket
import whois
import smtplib
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
    # Aquí utilizo una palabra clave como ejemplo, puedes personalizarla según tus necesidades
    if "adulto" in soup.get_text().lower():
        return True
    else:
        return False

def check_link(link):
    try:
        response = requests.get(link, timeout=5)
        
        if link.startswith("https"):
            if has_malware(response.content) or has_adult_content(response.content):
                return "lista negra"
            elif is_trustworthy(response.url):
                domain = tldextract.extract(response.url).registered_domain
                if domain.endswith("xvideos.com"):
                    return "lista negra"
                else:
                    return "lista verde"
            else:
                return "lista gris"
        else:
            return "lista gris"
    except:
        return "lista gris"

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
            if resultado == "lista verde":
                verde.append(link.strip())
            elif resultado == "lista negra":
                negra.append(link.strip())
            elif resultado == "lista gris":
                if has_redirect(link.strip()):
                    gris.append(link.strip())
                else:
                    resultado = "lista gris"
                    gris.append(link.strip())

        return render_template('index.html', verde=verde, gris=gris, negra=negra)

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



if __name__ == '__main__':
    app.run(debug=True)
