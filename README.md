## 🚀 Instalación completa

### 1. Instalar dependencias del sistema
```bash
sudo apt update
sudo apt install nmap john python3-pip -y

### 2. Instalar Ollama (IA local)
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama2  # o mistral, codellama

### 3. Instalar dependencias Python
```bash
pip install -r requirements.txt

### 4. Ejecutar la herramienta
```bash
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
