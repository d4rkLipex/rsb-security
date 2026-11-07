import sqlite3
import smtplib
import os
import time
import base64
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import deque
from typing import Dict, List
from http.server import HTTPServer, BaseHTTPRequestHandler

# ==============================================
# CONFIGURAÇÕES DO SISTEMA
# ==============================================
import os

# ...

CONFIG = {
    "BANCO_DADOS": "/tmp/rsb_threat.db" if os.path.exists("/tmp") else "rsb_threat.db",
    "PORTA_WEB": 8080,
    "LIMITE_TENTATIVAS": 5,
    "JANELA_TEMPO_SEG": 600,
    "SENHA_PAINEL": "admin123",
    "EMAIL_ATIVO": False,
    "EMAIL_SERVIDOR": "smtp.gmail.com",
    "EMAIL_PORTA": 587,
    "EMAIL_REMETENTE": "seuemail@gmail.com",
    "EMAIL_SENHA_APP": "",
    "EMAIL_DESTINATARIO": "destinatario@exemplo.com"}

PADROES_SUSPEITOS = [
    r"(\b(union|select|insert|delete|update|alter|drop)\b.*from)",
    r"(\.\/|\.\.\/|\\\/)",
    r"(<script|javascript:|on\w+\s*=)",
    r"(password|passwd|pwd).*(:|=).*[^\"]{4,}",
    r"(etc|passwd|boot\.ini|system32)",
    r"(\b(or|and)\b.*\d+\s*=\s*\d+)",
    r"(--|;|\|\/\*|cmd_shell)"
]

ips_bloqueados_temp: Dict[str, float] = {}
ips_bloqueados_perm: Dict[str, int] = {}
contador_bloqueios: Dict[str, int] = {}


# ==============================================
# RESTO DO SISTEMA
# ==============================================
def iniciar_banco():
    conn = sqlite3.connect(CONFIG["BANCO_DADOS"])
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ips_bloqueados (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            motivo TEXT,
            data_bloqueio TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            permanente BOOLEAN DEFAULT 0
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs_ataques (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            padrao_detectado TEXT,
            data_hora TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def verificar_ataque(texto: str) -> List[str]:
    detectados = []
    for padrao in PADROES_SUSPEITOS:
        import re
        if re.search(padrao, texto, re.IGNORECASE):
            detectados.append(padrao)
    return detectados


def verificar_bloqueio(ip: str) -> bool:
    if ip in ips_bloqueados_perm:
        return True
    if ip in ips_bloqueados_temp:
        if time.time() - ips_bloqueados_temp[ip] > CONFIG["JANELA_TEMPO_SEG"]:
            del ips_bloqueados_temp[ip]
            return False
        return True
    return False


def registrar_ataque(ip: str, padrao: str):
    conn = sqlite3.connect(CONFIG["BANCO_DADOS"])
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs_ataques (ip, padrao_detectado) VALUES (?, ?)", (ip, padrao))
    conn.commit()
    conn.close()


def bloquear_ip(ip: str, motivo: str):
    conn = sqlite3.connect(CONFIG["BANCO_DADOS"])
    cursor = conn.cursor()

    contador_bloqueios[ip] = contador_bloqueios.get(ip, 0) + 1

    if contador_bloqueios[ip] >= 3:
        ips_bloqueados_perm[ip] = 1
        cursor.execute("INSERT INTO ips_bloqueados (ip, motivo, permanente) VALUES (?, ?, 1)", (ip, motivo))
    else:
        ips_bloqueados_temp[ip] = time.time()
        cursor.execute("INSERT INTO ips_bloqueados (ip, motivo) VALUES (?, ?)", (ip, motivo))

    conn.commit()
    conn.close()

    if CONFIG["EMAIL_ATIVO"]:
        enviar_alerta_email(ip, motivo)


def enviar_alerta_email(ip: str, motivo: str):
    try:
        msg = MIMEMultipart()
        msg["From"] = CONFIG["EMAIL_REMETENTE"]
        msg["To"] = CONFIG["EMAIL_DESTINATARIO"]
        msg["Subject"] = "⚠️ ALERTA DE AMEAÇA DETECTADA - RSB Security"

        corpo = f"""
        IP suspeito: {ip}
        Motivo: {motivo}
        Data/Hora: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}

        --
        RSB Threat Detection v1.2
        """
        msg.attach(MIMEText(corpo, "plain"))

        servidor = smtplib.SMTP(CONFIG["EMAIL_SERVIDOR"], CONFIG["EMAIL_PORTA"])
        servidor.starttls()
        servidor.login(CONFIG["EMAIL_REMETENTE"], CONFIG["EMAIL_SENHA_APP"])
        servidor.send_message(msg)
        servidor.quit()
    except Exception as e:
        print(f"Erro ao enviar e-mail: {e}")


class PainelHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            senha = self.headers.get("Authorization")
            if not senha or f"Basic {base64.b64encode(f'admin:{CONFIG['SENHA_PAINEL']}'.encode()).decode()}" != senha:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="Painel RSB"')
                self.end_headers()
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()

            conn = sqlite3.connect(CONFIG["BANCO_DADOS"])
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM logs_ataques ORDER BY data_hora DESC LIMIT 50")
            logs = cursor.fetchall()
            cursor.execute("SELECT DISTINCT ip FROM ips_bloqueados")
            bloqueados = cursor.fetchall()
            conn.close()

            html = f"""
            <html><body style="background:#0f172a;color:#fff;font-family:Arial;padding:20px;">
                <h1 style="color:#22c55e;">🛡️ RSB Security - Painel de Controle</h1>
                <h3>IPs Bloqueados: {len(bloqueados)}</h3>
                <h3>Últimos Ataques Detectados:</h3>
                <table border="1" cellpadding="8" style="border-collapse:collapse;width:100%;margin-top:10px;">
                    <tr style="background:#1e293b;"><th>ID</th><th>IP</th><th>Padrão</th><th>Data/Hora</th></tr>
                    {"".join([f"<tr><td>{l[0]}</td><td>{l[1]}</td><td style='color:#f87171;'>{l[2][:50]}...</td><td>{l[3]}</td></tr>" for l in logs])}
                </table>
            </body></html>
            """
            self.wfile.write(html.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()


def verificar_requisicao(ip: str, caminho: str) -> bool:
    if verificar_bloqueio(ip):
        return False

    padroes = verificar_ataque(caminho)
    if padroes:
        registrar_ataque(ip, padroes[0])
        bloquear_ip(ip, f"Padrão detectado: {padroes[0]}")
        return False
    return True


def executar_servidor():
    iniciar_banco()
    print("✅ RSB THREAT DETECTION v1.2 - SISTEMA INICIADO")
    print(f"🌐 Painel: http://0.0.0.0:{CONFIG['PORTA_WEB']}")
    print(f"🔑 Senha: {CONFIG['SENHA_PAINEL']}")
    print(f"📧 Alerta por e-mail: {'ATIVADO' if CONFIG['EMAIL_ATIVO'] else 'DESATIVADO'}")

    server = HTTPServer(("0.0.0.0", CONFIG["PORTA_WEB"]), PainelHandler)
    server.serve_forever()


if __name__ == "__main__":
    from datetime import datetime

    executar_servidor()
