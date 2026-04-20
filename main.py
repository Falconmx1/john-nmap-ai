from fastapi import FastAPI, Request, Form, UploadFile, File, BackgroundTasks
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import nmap
import subprocess
import json
import os
import hashlib
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
import requests

app = FastAPI()
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")
nm = nmap.PortScanner()

# Configuración de Ollama
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama2"  # o "codellama", "mistral"

def query_ollama(prompt):
    """Consulta IA local via Ollama"""
    try:
        response = requests.post(OLLAMA_URL, json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False
        })
        return response.json()["response"]
    except:
        return "⚠️ Ollama no está corriendo. Instálalo con: curl -fsSL https://ollama.com/install.sh | sh"

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/scan")
async def scan_network(target: str = Form(...)):
    # Escaneo con nmap
    nm.scan(hosts=target, arguments='-sV -sS -T4 -O')
    results = []
    vulnerabilities = []
    
    for host in nm.all_hosts():
        host_info = {
            "host": host,
            "hostname": nm[host].hostname(),
            "state": nm[host].state(),
            "os": nm[host].get('osmatch', [{}])[0].get('name', 'Desconocido'),
            "ports": []
        }
        
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                service = nm[host][proto][port]
                port_info = {
                    "port": port,
                    "protocol": proto,
                    "name": service['name'],
                    "version": service.get('version', ''),
                    "product": service.get('product', ''),
                    "state": service['state']
                }
                host_info["ports"].append(port_info)
                
                # Detección de vulnerabilidades básicas
                if service['name'] == 'ssh' and port == 22:
                    vulnerabilities.append(f"⚠️ SSH expuesto en {host}:22 - Riesgo de fuerza bruta")
                if service['name'] in ['http', 'https']:
                    vulnerabilities.append(f"🌐 Web server en {host}:{port} - Posible vulnerabilidad web")
                if service['name'] == 'ftp':
                    vulnerabilities.append(f"📁 FTP anónimo? en {host}:21")
        
        results.append(host_info)
    
    # Análisis con IA
    ia_prompt = f"Analiza este escaneo de red y da recomendaciones de seguridad:\n{json.dumps(results, indent=2)}\nVulnerabilidades encontradas: {vulnerabilities}\nResponde en español, de forma profesional pero clara:"
    ia_analysis = query_ollama(ia_prompt)
    
    return {
        "scan_results": results, 
        "vulnerabilities": vulnerabilities,
        "ia_analysis": ia_analysis
    }

@app.post("/crack")
async def crack_hash(
    hash_text: str = Form(...), 
    hash_type: str = Form(...),
    wordlist: UploadFile = File(...)
):
    # Guardar wordlist subida
    wordlist_path = f"temp_{wordlist.filename}"
    with open(wordlist_path, "wb") as f:
        content = await wordlist.read()
        f.write(content)
    
    # Detectar formato si es automático
    hash_format = hash_type
    if hash_type == "auto":
        if len(hash_text) == 32:
            hash_format = "raw-md5"
        elif len(hash_text) == 40:
            hash_format = "raw-sha1"
        elif len(hash_text) == 64:
            hash_format = "raw-sha256"
        else:
            hash_format = "raw-md5"
    
    # Guardar hash
    with open("hash.txt", "w") as f:
        f.write(hash_text)
    
    # Ejecutar John
    try:
        result = subprocess.run(
            f"john --format={hash_format} --wordlist={wordlist_path} hash.txt --stdout",
            shell=True, capture_output=True, text=True, timeout=30
        )
        cracked = result.stdout.strip()
        
        # IA que sugiere mejores wordlists si no crackeó
        if not cracked:
            ia_suggestion = query_ollama(f"No pude crackear el hash {hash_text}. Sugiere 3 wordlists comunes para {hash_format} o técnicas alternativas:")
            return {"cracked_password": "No se pudo crackear", "ia_suggestion": ia_suggestion}
        
        return {"cracked_password": cracked, "ia_suggestion": "✅ Éxito! Revisa la contraseña encontrada."}
    except subprocess.TimeoutExpired:
        return {"cracked_password": "Timeout", "ia_suggestion": "El ataque tomó demasiado tiempo. Prueba con una wordlist más pequeña."}
    finally:
        os.remove(wordlist_path)
        os.remove("hash.txt")

@app.post("/generate-pdf")
async def generate_pdf_report(background_tasks: BackgroundTasks, scan_data: str = Form(...)):
    """Genera reporte PDF con análisis de IA"""
    data = json.loads(scan_data)
    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = f"static/{filename}"
    
    # Crear PDF
    doc = SimpleDocTemplate(filepath, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Título
    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor('#0f0'), alignment=1)
    story.append(Paragraph("Informe de Seguridad - john-nmap-ai", title_style))
    story.append(Spacer(1, 12))
    
    # Fecha
    story.append(Paragraph(f"Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Spacer(1, 12))
    
    # Resultados del escaneo
    story.append(Paragraph("Resultados del Escaneo", styles['Heading2']))
    for host in data.get('scan_results', []):
        story.append(Paragraph(f"Host: {host['host']} ({host['state']})", styles['Heading3']))
        story.append(Paragraph(f"SO: {host['os']}", styles['Normal']))
        
        # Tabla de puertos
        if host['ports']:
            table_data = [['Puerto', 'Protocolo', 'Servicio', 'Versión']]
            for port in host['ports']:
                table_data.append([str(port['port']), port['protocol'], port['name'], port['version']])
            table = Table(table_data)
            table.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.grey), ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke), ('ALIGN', (0,0), (-1,-1), 'CENTER'), ('GRID', (0,0), (-1,-1), 1, colors.black)]))
            story.append(table)
        story.append(Spacer(1, 12))
    
    # Vulnerabilidades
    story.append(Paragraph("Vulnerabilidades Detectadas", styles['Heading2']))
    for vuln in data.get('vulnerabilities', []):
        story.append(Paragraph(f"• {vuln}", styles['Normal']))
    story.append(Spacer(1, 12))
    
    # Análisis de IA
    story.append(Paragraph("Análisis y Recomendaciones de IA", styles['Heading2']))
    story.append(Paragraph(data.get('ia_analysis', 'No disponible'), styles['Normal']))
    
    # Generar PDF
    doc.build(story)
    
    return {"pdf_url": f"/static/{filename}", "filename": filename}
