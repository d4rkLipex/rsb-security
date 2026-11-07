import sqlite3
import smtplib
import os
import time
import base64
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import deque
from typing import Dict
from http.server import HTTPServer, BaseHTTPRequestHandler

# ========================================
# CONFIGURAÇÕES DO SISTEMA
# ========================================
# Caminho com permissão de escrita no Render
"BANCO_DADOS": "/tmp/rsb_threat.db",
    "PORTA_WEB": 8080,
    "LIMITE_TENTATIVAS": 5,
    "JANELA_TEMPO_SEG": 600,
    "SENHA_PAINEL": "admin123",
    "EMAIL_ATIVO": False,
    "EMAIL_SERVIDOR": "smtp.gmail.com",
    "EMAIL_PORTA": 587,
    "EMAIL_REMETENTE": "seuemail@gmail.com",
    "EMAIL_SENHA_APP": "",
    "EMAIL_DESTINATARIO": "destinatario@exemplo.com"

PADROES_SUSPEITOS = [
    r"(\b(union|select|insert|delete|update|alter|drop)\b.*from)",
    r"(\.\./|\.\.\\\\)",
    r"(<script|javascript:|on\w+\s*=)",
    r"(password|passwd|pwd).*(:=|:).*['\"].{4,}",
    r"(etc/passwd|boot.ini|system32)",
    r"(\b(or|and)\b.*\d+\s*=\s*\d+)",
    r"(--|;|/\*|\*/|xp_cmdshell)",
]

ips_bloqueados_temp: Dict[str, float] = {}
ips_bloqueados_perm: Dict[str, int] = {}
contador_bloqueios: Dict[str, int] = {}


# ========================================
# GEOLOCALIZAÇÃO
# ========================================
def get_pais_ip(ip: str) -> str:
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127."):
        return "🔒 Local/Interno"
    if ip.startswith("198.51."):
        return "🇺🇸 Estados Unidos"
    if ip.startswith("200.") or ip.startswith("177.") or ip.startswith("18."):
        return "🇧🇷 Brasil"
    return "🌍 Desconhecido"


# ========================================
# BANCO DE DADOS
# ========================================
def iniciar_banco():
    conn = sqlite3.connect(CONFIG["BANCO_DADOS"])
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS clientes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            chave_api TEXT UNIQUE NOT NULL,
            email_alerta TEXT,
            status TEXT DEFAULT 'ativo',
            criado_em TEXT NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS eventos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cliente_id INTEGER NOT NULL,
            tipo TEXT NOT NULL,
            descricao TEXT,
            endereco_ip TEXT,
            pais TEXT DEFAULT 'Desconhecido',
            data_hora TEXT NOT NULL,
            FOREIGN KEY (cliente_id) REFERENCES clientes(id)
        )
    """)
    conn.commit()
    conn.close()


def cadastrar_cliente(nome: str, email: str = "") -> str:
    import uuid
    chave = str(uuid.uuid4()).replace("-", "")
    conn = sqlite3.connect(CONFIG["BANCO_DADOS"])
    c = conn.cursor()
    c.execute("INSERT INTO clientes (nome, chave_api, email_alerta, criado_em) VALUES (?, ?, ?, ?)",
              (nome, chave, email, time.strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    return chave


def listar_clientes():
    conn = sqlite3.connect(CONFIG["BANCO_DADOS"])
    c = conn.cursor()
    c.execute("SELECT id, nome, chave_api, status FROM clientes")
    res = c.fetchall()
    conn.close()
    return res


def obter_estatisticas():
    conn = sqlite3.connect(CONFIG["BANCO_DADOS"])
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM eventos")
    total = c.fetchone()[0]
    hoje = time.strftime("%Y-%m-%d")
    c.execute("SELECT COUNT(*) FROM eventos WHERE data_hora LIKE ?", (f"{hoje}%",))
    hoje_qtd = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM eventos WHERE tipo LIKE '%falha%'")
    falhas = c.fetchone()[0]
    c.execute("SELECT COUNT(DISTINCT endereco_ip) FROM eventos")
    ips_unicos = c.fetchone()[0]
    conn.close()
    return {
        "total": total,
        "hoje": hoje_qtd,
        "falhas": falhas,
        "ips_unicos": ips_unicos,
        "bloqueados_perm": len(ips_bloqueados_perm)
    }


# ========================================
# E-MAIL COM FORMATO BONITO
# ========================================
def enviar_alerta_email(ip: str, bloqueio_perm: bool):
    if not CONFIG["EMAIL_ATIVO"]:
        return
    try:
        msg = MIMEMultipart()
        msg["From"] = CONFIG["EMAIL_REMETENTE"]
        msg["To"] = CONFIG["EMAIL_DESTINATARIO"]
        tipo = "PERMANENTE" if bloqueio_perm else "Temporário (1h)"
        msg["Subject"] = f"🚨 ALERTA DE SEGURANÇA — IP {ip} Bloqueado {tipo}"

        pais = get_pais_ip(ip)
        ano = time.strftime("%Y")
        corpo = f"""
<html>
<body style="font-family:Arial; background:#f4f4f4; padding:20px;">
    <div style="background:white; padding:25px; border-radius:8px; max-width:600px;">
        <h2 style="color:#c0392b;">🚨 RSB THREAT DETECTION</h2>
        <p><strong>IP suspeito:</strong> {ip}</p>
        <p><strong>Localização:</strong> {pais}</p>
        <p><strong>Ação:</strong> BLOQUEIO {tipo}</p>
        <hr>
        <p>Acesse o painel: <a href="http://localhost:{CONFIG['PORTA_WEB']}">http://localhost:{CONFIG['PORTA_WEB']}</a></p>
        <p style="color:#888; font-size:12px;">RSB Security © {ano}</p>
    </div>
</body>
</html>
        """
        msg.attach(MIMEText(corpo, "html"))

        servidor = smtplib.SMTP(CONFIG["EMAIL_SERVIDOR"], CONFIG["EMAIL_PORTA"])
        servidor.starttls()
        servidor.login(CONFIG["EMAIL_REMETENTE"], CONFIG["EMAIL_SENHA_APP"])
        servidor.send_message(msg)
        servidor.quit()
        print("[E-MAIL] Enviado com sucesso ✅")
    except Exception as e:
        print(f"[ERRO E-MAIL] {e}")


# ========================================
# DETECÇÃO DE AMEAÇAS
# ========================================
class AgenteRSB:
    def __init__(self, chave_api=None):
        self.chave_api = chave_api
        self.cliente_id = 1
        self.falhas_por_ip: Dict[str, deque] = {}

    def verificar_bloqueio(self, ip: str) -> str:
        if ip in ips_bloqueados_perm:
            return "PERM"
        if ip in ips_bloqueados_temp:
            if time.time() - ips_bloqueados_temp[ip] > CONFIG["TEMPO_BLOQUEIO_SEG"]:
                del ips_bloqueados_temp[ip]
                return ""
            return "TEMP"
        return ""

    def registrar(self, ip: str, descricao: str = "Tentativa de acesso") -> str:
        bloqueio = self.verificar_bloqueio(ip)
        if bloqueio:
            return bloqueio

        agora = time.time()
        data_hora = time.strftime("%Y-%m-%d %H:%M:%S")
        pais = get_pais_ip(ip)

        conn = sqlite3.connect(CONFIG["BANCO_DADOS"])
        c = conn.cursor()
        c.execute("""
            INSERT INTO eventos (cliente_id, tipo, descricao, endereco_ip, pais, data_hora)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (1, "login_falhou", descricao, ip, pais, data_hora))
        conn.commit()
        conn.close()

        if ip not in self.falhas_por_ip:
            self.falhas_por_ip[ip] = deque()
        self.falhas_por_ip[ip].append(agora)

        while self.falhas_por_ip[ip] and agora - self.falhas_por_ip[ip][0] > CONFIG["JANELA_TEMPO_SEG"]:
            self.falhas_por_ip[ip].popleft()

        if len(self.falhas_por_ip[ip]) >= CONFIG["LIMITE_TENTATIVAS"]:
            contador_bloqueios[ip] = contador_bloqueios.get(ip, 0) + 1
            if contador_bloqueios[ip] >= CONFIG["LIMITE_BLOQUEIOS_PERMANENTE"]:
                ips_bloqueados_perm[ip] = contador_bloqueios[ip]
                enviar_alerta_email(ip, True)
                return "PERM"
            else:
                ips_bloqueados_temp[ip] = agora
                enviar_alerta_email(ip, False)
                return "TEMP"
        return ""


# ========================================
# LOGIN DO PAINEL
# ========================================
def verificar_login(cabecalhos) -> bool:
    auth = cabecalhos.get("Authorization")
    if not auth:
        return False
    try:
        tipo, cod = auth.split(" ", 1)
        if tipo.lower() == "basic":
            dec = base64.b64decode(cod).decode("utf-8")
            usuario, senha = dec.split(":", 1)
            return usuario == "admin" and senha == CONFIG["SENHA_PAINEL"]
    except:
        pass
    return False


# ========================================
# PAINEL WEB COMPLETO
# ========================================
class PainelHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if not verificar_login(self.headers):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="RSB Security"')
            self.end_headers()
            self.wfile.write(
                "<h1 style='color:red; text-align:center; margin-top:50px;'>Acesso Negado — Faça Login</h1>".encode(
                    "utf-8"))
            return

        if self.path == "/exportar":
            self.exportar_csv()
            return

        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()

        stats = obter_estatisticas()

        conn = sqlite3.connect(CONFIG["BANCO_DADOS"])
        c = conn.cursor()
        c.execute("""
            SELECT e.data_hora, e.endereco_ip, e.pais, e.tipo, e.descricao
            FROM eventos e ORDER BY e.id DESC LIMIT 20
        """)
        eventos = c.fetchall()
        conn.close()

        html_eventos = ""
        for ev in eventos:
            cor = "#e67e22" if "falha" in str(ev[3]).lower() else "#27ae60"
            html_eventos += f"<tr><td>{ev[0]}</td><td>{ev[1]}</td><td>{ev[2]}</td><td style='color:{cor}'>{ev[3]}</td><td>{ev[4]}</td></tr>"

        html_bloq_temp = ""
        if ips_bloqueados_temp:
            html_bloq_temp = "<h3 style='color:#e67e22; margin-top:25px;'>⏱️ Bloqueios Temporários</h3><ul>"
            for ip, t in ips_bloqueados_temp.items():
                rest = max(0, (CONFIG["TEMPO_BLOQUEIO_SEG"] - (time.time() - t)) // 60)
                html_bloq_temp += f"<li>{ip} — Expira em {int(rest)} min</li>"
            html_bloq_temp += "</ul>"

        html_bloq_perm = ""
        if ips_bloqueados_perm:
            html_bloq_perm = "<h3 style='color:#c0392b; margin-top:25px;'>🚫 Bloqueios Permanentes</h3><ul>"
            for ip, qtd in ips_bloqueados_perm.items():
                html_bloq_perm += f"<li>{ip} — {qtd} reincidências</li>"
            html_bloq_perm += "</ul>"

        html_clientes = ""
        clientes = listar_clientes()
        if len(clientes) > 0:
            html_clientes = "<h3 style='color:#3498db; margin-top:25px;'>👥 Clientes Ativos</h3><ul>"
            for cli in clientes:
                html_clientes += f"<li><strong>{cli[1]}</strong> — {cli[3]}</li>"
            html_clientes += "</ul>"

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>RSB THREAT DETECTION v2.0</title>
    <style>
        body {{ font-family: Arial; background: #0f1419; color: #fff; padding: 25px; }}
        h1 {{ text-align: center; color: #00d9ff; }}
        .estat {{ display: flex; gap: 15px; margin: 25px 0; flex-wrap: wrap; }}
        .card {{ background: #1a1f2e; padding: 20px; border-radius: 8px; flex: 1; min-width: 140px; text-align: center; }}
        .card .num {{ font-size: 28px; font-weight: bold; color: #00d9ff; }}
        .card .label {{ color: #888; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th {{ background: #242938; padding: 12px; text-align: left; border-bottom: 2px solid #00d9ff; }}
        td {{ padding: 12px; border-bottom: 1px solid #2c3246; }}
        .export {{ margin: 20px 0; }}
        .export a {{ color: #00d9ff; text-decoration: none; }}
    </style>
</head>
<body>
    <h1>🛡️ RSB THREAT DETECTION</h1>
    <p style="text-align:center; color:#888;">Monitoramento de Segurança em Tempo Real</p>

    <div class="estat">
        <div class="card">
            <div class="num">{stats['total']}</div>
            <div class="label">Total Eventos</div>
        </div>
        <div class="card">
            <div class="num" style="color:#2ecc71;">{stats['hoje']}</div>
            <div class="label">Hoje</div>
        </div>
        <div class="card">
            <div class="num" style="color:#e67e22;">{stats['falhas']}</div>
            <div class="label">Falhas</div>
        </div>
        <div class="card">
            <div class="num" style="color:#9b59b6;">{stats['ips_unicos']}</div>
            <div class="label">IPs Únicos</div>
        </div>
        <div class="card">
            <div class="num" style="color:#e74c3c;">{stats['bloqueados_perm']}</div>
            <div class="label">Bloq. Perm.</div>
        </div>
    </div>

    <div class="export">
        <a href="/exportar" style="background:#00d9ff; color:#000; padding:10px 20px; border-radius:5px; font-weight:bold;">📤 Exportar CSV</a>
    </div>

    <table>
        <tr>
            <th>Data/Hora</th>
            <th>IP</th>
            <th>País</th>
            <th>Tipo</th>
            <th>Detalhe</th>
        </tr>
        {html_eventos}
    </table>

    {html_bloq_temp}
    {html_bloq_perm}
    {html_clientes}

</body>
</html>
        """.encode("utf-8")
        self.wfile.write(html)

    def exportar_csv(self):
        self.send_response(200)
        self.send_header("Content-type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="rsb_relatorio.csv"')
        self.end_headers()

        conn = sqlite3.connect(CONFIG["BANCO_DADOS"])
        c = conn.cursor()
        c.execute("SELECT data_hora, endereco_ip, pais, tipo, descricao FROM eventos ORDER BY id DESC")
        eventos = c.fetchall()
        conn.close()

        csv = "Data/Hora,IP,País,Tipo,Detalhe\n"
        for ev in eventos:
            csv += f"{ev[0]},{ev[1]},{ev[2]},{ev[3]},{ev[4]}\n"

        self.wfile.write(csv.encode("utf-8"))

    def log_message(self, format, *args):
        return


def iniciar_painel():
    servidor = HTTPServer(("0.0.0.0", CONFIG["PORTA_WEB"]), PainelHandler)
    print(f"[PAINEL] http://localhost:{CONFIG['PORTA_WEB']}")
    print(f"[LOGIN] admin / {CONFIG['SENHA_PAINEL']}")
    servidor.serve_forever()


# ========================================
# EXECUÇÃO PRINCIPAL
# ========================================
if __name__ == "__main__":
    print("=" * 50)
    print("RSB THREAT DETECTION v2.0 — SISTEMA COMPLETO")
    print("=" * 50)

    if not os.path.exists(CONFIG["BANCO_DADOS"]):
        iniciar_banco()

    chave = cadastrar_cliente("Empresa Principal")
    agente = AgenteRSB(chave)
for i in range(1, 8):
    status = agente.registrar("198.51.100.77", f"Tentativa {i} — senha incorreta")
    if status == "PERM":
        print(f"Tentativa {i} — BLOQUEIO PERMANENTE")
    elif status == "TEMP":
        print(f"Tentativa {i} — BLOQUEADO")
    else:
        print(f"Tentativa {i} — Registrada")
# Inicia o painel web
import threading
from http.server import HTTPServer

def iniciar_painel():
    servidor = HTTPServer(("0.0.0.0", CONFIG["PORTA_WEB"]), PainelHandler)
    print("\n🌐 PAINEL ONLINE: http://localhost:8080")
    print("🔐 Login: admin / Senha: HappyNation")
#  servidor.serve_forever()

#threading.Thread(target=iniciar_painel, daemon=True).start()

# Mantém o sistema rodando
#while True:
#   import time
#   time.sleep(60)
    from http.server import HTTPServer
# --- WSGI para PythonAnywhere ---
from http.server import HTTPServer

if __name__ == "__main__":
    print("✅ Sistema RSB carregado! Acesse pelo link do site.")
else:
    # Variável que o PythonAnywhere PRECISA ter o nome exato
    application = PainelHandler