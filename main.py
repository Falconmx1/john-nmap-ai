from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import nmap
import subprocess
import json

app = FastAPI()
templates = Jinja2Templates(directory="templates")
nm = nmap.PortScanner()

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/scan")
async def scan_network(target: str = Form(...)):
    # Escaneo con nmap
    nm.scan(hosts=target, arguments='-sV -sS -T4')
    results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                service = nm[host][proto][port]
                results.append({
                    "host": host,
                    "port": port,
                    "name": service['name'],
                    "version": service.get('version', '')
                })
    
    # Simulación de IA: analiza resultados y da recomendaciones
    ia_recommendations = []
    for r in results:
        if "ssh" in r['name'] and r['port'] == 22:
            ia_recommendations.append(f"🔐 Puerto SSH abierto en {r['host']}. Recomiendo probar John con diccionario personalizado.")
        if "http" in r['name']:
            ia_recommendations.append(f"🌐 Servidor web en {r['host']}:{r['port']} ({r['version']}). Posible vulnerabilidad web.")
    
    return {"scan_results": results, "ia_recommendations": ia_recommendations}

@app.post/crack
async def crack_hash(hash_text: str = Form(...), wordlist: str = Form(...)):
    # Integración con John (requiere tenerlo instalado local)
    with open("hash.txt", "w") as f:
        f.write(hash_text)
    
    result = subprocess.run(
        f"john --format=raw-md5 --wordlist={wordlist} hash.txt --stdout",
        shell=True, capture_output=True, text=True
    )
    
    return {"cracked_password": result.stdout.strip()}
