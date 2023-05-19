from flask import Flask, render_template, request
import requests
import tldextract
from bs4 import BeautifulSoup

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

@app.route('/resultados', methods=['GET', 'POST'])
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

        return render_template('resultados.html', verde=verde, gris=gris, negra=negra)

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
