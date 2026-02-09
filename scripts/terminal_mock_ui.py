#!/usr/bin/env python3
"""
McAfee OpenClaw Pre-Install Auditor - Terminal Mock UI
Demonstrates the CLI/brew install intercept experience with McAfee branding.

Usage:
    python terminal_mock_ui.py                    # Full interactive demo
    python terminal_mock_ui.py --scenario npm     # npm install intercept
    python terminal_mock_ui.py --scenario brew    # brew install intercept
    python terminal_mock_ui.py --scenario pip     # pip install intercept
"""

import sys
import time
import os
import argparse
from datetime import datetime

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = WHITE = MAGENTA = BLUE = RESET = ""
        LIGHTRED_EX = LIGHTGREEN_EX = LIGHTYELLOW_EX = LIGHTCYAN_EX = ""
        LIGHTWHITE_EX = LIGHTMAGENTA_EX = LIGHTBLUE_EX = ""
    class Back:
        RED = GREEN = YELLOW = CYAN = WHITE = BLACK = RESET = ""
        LIGHTRED_EX = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  McAfee ASCII Wordmark
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

MCAFEE_WORDMARK = f"""\
{Fore.RED}{Style.BRIGHT}  __  __   ____    _    {Fore.LIGHTRED_EX}_____  _____  _____{Style.RESET_ALL}
{Fore.RED}{Style.BRIGHT} |  \\/  | / ___|  / \\   {Fore.LIGHTRED_EX}|  ___|| ____|| ____|{Style.RESET_ALL}
{Fore.RED}{Style.BRIGHT} | |\\/| || |     / _ \\  {Fore.LIGHTRED_EX}| |_   |  _|  |  _|{Style.RESET_ALL}
{Fore.RED}{Style.BRIGHT} | |  | || |___ / ___ \\ {Fore.LIGHTRED_EX}|  _|  | |___ | |___{Style.RESET_ALL}
{Fore.RED}{Style.BRIGHT} |_|  |_| \\____/_/   \\_\\{Fore.LIGHTRED_EX}|_|    |_____||_____|{Style.RESET_ALL}"""


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  Helper Functions
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def typewriter(text, delay=0.02):
    """Print text with typewriter effect."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def slow_print(text, delay=0.03):
    """Print text with slight delay per character."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def progress_bar(label, duration=3.0, width=40, color=Fore.CYAN):
    """Animated progress bar."""
    steps = width
    for i in range(steps + 1):
        pct = int(100 * i / steps)
        filled = "â–ˆ" * i
        empty = "â–‘" * (steps - i)
        sys.stdout.write(f"\r  {color}{label} [{filled}{empty}] {pct}%{Style.RESET_ALL}")
        sys.stdout.flush()
        time.sleep(duration / steps)
    print()


def spinner(label, duration=2.0):
    """Animated spinner."""
    chars = "â ‹â ™â ¹â ¸â ¼â ´â ¦â §â ‡â "
    end_time = time.time() + duration
    i = 0
    while time.time() < end_time:
        sys.stdout.write(f"\r  {Fore.YELLOW}{chars[i % len(chars)]} {label}{Style.RESET_ALL}")
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    sys.stdout.write(f"\r  {Fore.GREEN}âœ“ {label}{Style.RESET_ALL}                    \n")


def print_box(lines, color=Fore.CYAN, width=68):
    """Print text in a bordered box."""
    print(f"{color}â•”{'â•' * width}â•—{Style.RESET_ALL}")
    for line in lines:
        padded = line.ljust(width)[:width]
        print(f"{color}â•‘{Style.RESET_ALL} {padded}{color}â•‘{Style.RESET_ALL}")
    print(f"{color}â•š{'â•' * width}â•{Style.RESET_ALL}")


def print_warning_box(lines, width=68):
    """Print a red warning box."""
    print(f"{Fore.RED}{Style.BRIGHT}â•”{'â•' * width}â•—{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}â•‘{Back.RED}{Fore.WHITE}{Style.BRIGHT}{'âš   SECURITY WARNING  âš ':^{width}}{Style.RESET_ALL}{Fore.RED}{Style.BRIGHT}â•‘{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}â• {'â•' * width}â•£{Style.RESET_ALL}")
    for line in lines:
        padded = line.ljust(width)[:width]
        print(f"{Fore.RED}{Style.BRIGHT}â•‘{Style.RESET_ALL} {padded}{Fore.RED}{Style.BRIGHT}â•‘{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}â•š{'â•' * width}â•{Style.RESET_ALL}")


def print_safe_box(lines, width=68):
    """Print a green safe box."""
    print(f"{Fore.GREEN}{Style.BRIGHT}â•”{'â•' * width}â•—{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{Style.BRIGHT}â•‘{Back.GREEN}{Fore.WHITE}{Style.BRIGHT}{'âœ“  SCAN COMPLETE - LOW RISK  âœ“':^{width}}{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}â•‘{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{Style.BRIGHT}â• {'â•' * width}â•£{Style.RESET_ALL}")
    for line in lines:
        padded = line.ljust(width)[:width]
        print(f"{Fore.GREEN}{Style.BRIGHT}â•‘{Style.RESET_ALL} {padded}{Fore.GREEN}{Style.BRIGHT}â•‘{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{Style.BRIGHT}â•š{'â•' * width}â•{Style.RESET_ALL}")


def print_divider(char="â”€", width=70, color=Fore.CYAN):
    print(f"{color}{char * width}{Style.RESET_ALL}")


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  Full Banner Display
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def print_full_banner():
    """Display the full McAfee branded banner."""
    print()
    print(MCAFEE_WORDMARK)
    print()
    print(f"{Fore.WHITE}{Style.BRIGHT}{'Pre-Install Security Auditor':^60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'Protecting you before you install':^60}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{Style.BRIGHT}{'â”€' * 60:^60}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{'v1.0.0  â”‚  AI Agent Framework Scanner  â”‚  Real-time Protection':^60}{Style.RESET_ALL}")
    print()


def print_compact_banner():
    """Display compact banner."""
    print()
    print(MCAFEE_WORDMARK)
    print()
    print(f"{Fore.RED}{Style.BRIGHT}    McAfee{Fore.WHITE} Pre-Install Security Auditor{Style.RESET_ALL}")
    print(f"{Fore.CYAN}    â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€{Style.RESET_ALL}")
    print()


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  Scenario: npm install intercept
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def demo_npm_install():
    """Simulate npm install being intercepted by McAfee scanner."""
    clear_screen()
    print()
    print(f"{Fore.WHITE}{Style.BRIGHT}$ npm install -g @openclaw/cli{Style.RESET_ALL}")
    print()
    time.sleep(1)

    # Show npm starting
    print(f"{Fore.WHITE}npm {Fore.CYAN}info{Style.RESET_ALL} it worked if it ends with ok")
    print(f"{Fore.WHITE}npm {Fore.CYAN}info{Style.RESET_ALL} using npm@10.2.4")
    print(f"{Fore.WHITE}npm {Fore.CYAN}info{Style.RESET_ALL} using node@v22.0.0")
    time.sleep(0.5)
    print(f"{Fore.WHITE}npm {Fore.CYAN}info{Style.RESET_ALL} resolving @openclaw/cli@latest")
    time.sleep(0.8)

    # McAfee intercept
    print()
    print(f"{Fore.YELLOW}{Style.BRIGHT}{'â”€' * 70}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{Style.BRIGHT}  McAfee Pre-Install Auditor has intercepted this installation{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{Style.BRIGHT}{'â”€' * 70}{Style.RESET_ALL}")
    print()
    time.sleep(0.5)

    print_compact_banner()

    # Scanning phases
    spinner("Resolving package metadata...", 1.5)
    spinner("Checking package registry signatures...", 1.0)
    progress_bar("Scanning dependencies (247 packages)", 3.0, 40, Fore.CYAN)
    spinner("Analyzing postinstall scripts...", 2.0)
    progress_bar("Source code pattern analysis", 4.0, 40, Fore.CYAN)
    spinner("Checking known vulnerability database...", 1.5)
    spinner("Evaluating supply chain risk...", 1.0)
    print()

    # Show findings
    print_warning_box([
        "",
        f"{Fore.RED}  Package: @openclaw/cli@1.2.3{Style.RESET_ALL}                              ",
        f"{Fore.RED}  Risk Score: 87/100 (CRITICAL){Style.RESET_ALL}                             ",
        "",
        f"  {Fore.RED}â– {Style.RESET_ALL} 3 Critical vulnerabilities found                         ",
        f"  {Fore.YELLOW}â– {Style.RESET_ALL} 7 High severity issues                                  ",
        f"  {Fore.YELLOW}â– {Style.RESET_ALL} 12 Medium severity issues                               ",
        "",
        f"  {Fore.RED}CRITICAL:{Style.RESET_ALL} CVE-2026-25253 - Token exfiltration via gatewayUrl",
        f"  {Fore.RED}CRITICAL:{Style.RESET_ALL} Postinstall script executes remote payload         ",
        f"  {Fore.RED}CRITICAL:{Style.RESET_ALL} Accesses ~/.solana/id.json (crypto wallet)         ",
        "",
        f"  {Fore.YELLOW}HIGH:{Style.RESET_ALL} 47 unpinned dependencies (supply chain risk)         ",
        f"  {Fore.YELLOW}HIGH:{Style.RESET_ALL} Connects to known malicious IP: 91.92.242.30         ",
        f"  {Fore.YELLOW}HIGH:{Style.RESET_ALL} Contains obfuscated eval() calls                     ",
        "",
    ])

    print()
    print(f"  {Fore.RED}{Style.BRIGHT}RECOMMENDATION: DO NOT INSTALL{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}This package contains known security threats that could{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}compromise your system credentials and crypto wallets.{Style.RESET_ALL}")
    print()
    print(f"  {Fore.CYAN}[V]{Style.RESET_ALL} View full report    {Fore.CYAN}[I]{Style.RESET_ALL} Install anyway    {Fore.CYAN}[C]{Style.RESET_ALL} Cancel installation")
    print(f"  {Fore.CYAN}[R]{Style.RESET_ALL} Report to McAfee    {Fore.CYAN}[S]{Style.RESET_ALL} Safe alternative")
    print()

    choice = input(f"  {Fore.YELLOW}Your choice [C]: {Style.RESET_ALL}").strip().upper() or "C"

    if choice == "C":
        print()
        print(f"  {Fore.GREEN}âœ“ Installation cancelled. Your system is protected.{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}  Full report saved: ~/mcafee-reports/openclaw_audit_2026.html{Style.RESET_ALL}")
    elif choice == "I":
        print()
        print(f"  {Fore.RED}âš  Installing with known risks. McAfee will monitor runtime behavior.{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}  Runtime protection: ENABLED{Style.RESET_ALL}")
    elif choice == "V":
        print()
        print(f"  {Fore.CYAN}Opening report in browser...{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}  ~/mcafee-reports/openclaw_audit_2026.html{Style.RESET_ALL}")
    elif choice == "S":
        print()
        print(f"  {Fore.GREEN}Recommended safe alternatives:{Style.RESET_ALL}")
        print(f"    1. Use OpenClaw in Docker sandbox (--sandbox mode)")
        print(f"    2. Install with --no-scripts flag")
        print(f"    3. Use McAfee Verified version from enterprise registry")
    print()


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  Scenario: brew install intercept
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def demo_brew_install():
    """Simulate brew install being intercepted by McAfee scanner."""
    clear_screen()
    print()
    print(f"{Fore.WHITE}{Style.BRIGHT}$ brew install openclaw{Style.RESET_ALL}")
    print()
    time.sleep(1)

    print(f"{Fore.GREEN}==>{Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT} Downloading https://github.com/openclaw/openclaw/releases/v1.2.3{Style.RESET_ALL}")
    time.sleep(0.5)
    print(f"{Fore.GREEN}==>{Style.RESET_ALL} Downloading from https://objects.githubusercontent.com/...")
    time.sleep(0.8)
    print(f"######################################################################## 100.0%")
    time.sleep(0.3)

    # McAfee intercept
    print()
    print(f"{Fore.YELLOW}{Style.BRIGHT}{'â”€' * 70}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{Style.BRIGHT}  McAfee Pre-Install Auditor: Scanning before installation...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{Style.BRIGHT}{'â”€' * 70}{Style.RESET_ALL}")
    print()
    time.sleep(0.5)

    print_compact_banner()

    spinner("Verifying code signature...", 1.5)
    spinner("Checking binary hash against threat database...", 2.0)
    progress_bar("Analyzing bundled dependencies", 3.0, 40, Fore.CYAN)
    spinner("Scanning for known CVEs...", 1.5)
    spinner("Checking network behavior patterns...", 1.0)
    progress_bar("Runtime behavior prediction", 2.0, 40, Fore.CYAN)
    print()

    # Show findings
    print_warning_box([
        "",
        f"{Fore.RED}  Package: openclaw v1.2.3 (Homebrew){Style.RESET_ALL}                         ",
        f"{Fore.RED}  Risk Score: 92/100 (CRITICAL){Style.RESET_ALL}                             ",
        "",
        f"  {Fore.RED}â– {Style.RESET_ALL} 5 Critical findings    {Fore.YELLOW}â– {Style.RESET_ALL} 8 High    â–  15 Medium      ",
        "",
        f"  {Fore.RED}CRITICAL:{Style.RESET_ALL} Binary connects to C2 server on first run         ",
        f"  {Fore.RED}CRITICAL:{Style.RESET_ALL} Requests full disk access via entitlements         ",
        f"  {Fore.RED}CRITICAL:{Style.RESET_ALL} postinstall hooks execute unsigned scripts         ",
        f"  {Fore.RED}CRITICAL:{Style.RESET_ALL} Known CVE-2026-25253 (auth bypass)                ",
        f"  {Fore.RED}CRITICAL:{Style.RESET_ALL} Disables macOS Gatekeeper (xattr -c)              ",
        "",
        f"  {Fore.YELLOW}HIGH:{Style.RESET_ALL} WebSocket allows localhost CSWSH attacks             ",
        f"  {Fore.YELLOW}HIGH:{Style.RESET_ALL} Default config exposes admin API on 0.0.0.0          ",
        "",
    ])

    print()
    print(f"  {Fore.RED}{Style.BRIGHT}âš   DO NOT INSTALL - CRITICAL THREATS DETECTED{Style.RESET_ALL}")
    print()
    print(f"  {Fore.CYAN}[V]{Style.RESET_ALL} View full report    {Fore.CYAN}[I]{Style.RESET_ALL} Install anyway    {Fore.CYAN}[C]{Style.RESET_ALL} Cancel installation")
    print()

    choice = input(f"  {Fore.YELLOW}Your choice [C]: {Style.RESET_ALL}").strip().upper() or "C"

    if choice == "C":
        print()
        print(f"  {Fore.GREEN}âœ“ Installation cancelled. Your system is protected.{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}  Audit report: ~/mcafee-reports/brew_openclaw_audit.html{Style.RESET_ALL}")
    elif choice == "I":
        print()
        print(f"  {Fore.RED}âš  Proceeding with installation. Runtime monitoring ACTIVE.{Style.RESET_ALL}")
    print()


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  Scenario: pip install intercept
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def demo_pip_install():
    """Simulate pip install being intercepted by McAfee scanner."""
    clear_screen()
    print()
    print(f"{Fore.WHITE}{Style.BRIGHT}$ pip install openclaw-agent{Style.RESET_ALL}")
    print()
    time.sleep(1)

    print(f"Collecting openclaw-agent")
    time.sleep(0.3)
    print(f"  Downloading openclaw_agent-0.8.1-py3-none-any.whl (2.4 MB)")
    time.sleep(0.5)
    print(f"     â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â” 2.4/2.4 MB 12.3 MB/s")
    time.sleep(0.3)

    # McAfee intercept
    print()
    print(f"{Fore.YELLOW}{Style.BRIGHT}{'â”€' * 70}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{Style.BRIGHT}  McAfee Pre-Install Auditor: Scanning Python package...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{Style.BRIGHT}{'â”€' * 70}{Style.RESET_ALL}")
    print()
    time.sleep(0.5)

    print_compact_banner()

    spinner("Inspecting setup.py / pyproject.toml...", 1.5)
    spinner("Checking PyPI package integrity...", 1.0)
    progress_bar("Scanning package source code", 3.0, 40, Fore.CYAN)
    spinner("Analyzing dependency tree (34 packages)...", 2.0)
    spinner("Checking for typosquatting indicators...", 1.0)
    print()

    # Safe result
    print_safe_box([
        "",
        f"  Package: openclaw-agent v0.8.1 (PyPI)                              ",
        f"  Risk Score: {Fore.GREEN}18/100 (LOW){Style.RESET_ALL}                                        ",
        "",
        f"  {Fore.GREEN}âœ“{Style.RESET_ALL} No critical vulnerabilities found                          ",
        f"  {Fore.GREEN}âœ“{Style.RESET_ALL} Package signature verified                                 ",
        f"  {Fore.GREEN}âœ“{Style.RESET_ALL} No suspicious postinstall scripts                          ",
        f"  {Fore.GREEN}âœ“{Style.RESET_ALL} No credential harvesting patterns                          ",
        "",
        f"  {Fore.YELLOW}NOTICE:{Style.RESET_ALL} 2 medium-severity findings:                           ",
        f"    - urllib3 < 2.0.7 has known CVE (update recommended)              ",
        f"    - 3 unpinned transitive dependencies                              ",
        "",
    ])

    print()
    print(f"  {Fore.GREEN}{Style.BRIGHT}âœ“  SAFE TO INSTALL{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}  Proceeding with installation...{Style.RESET_ALL}")
    print()
    time.sleep(1)
    print(f"Installing collected packages: openclaw-agent")
    print(f"Successfully installed openclaw-agent-0.8.1")
    print()
    print(f"  {Fore.CYAN}McAfee runtime protection: ENABLED{Style.RESET_ALL}")
    print()


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  Scenario: Skill install from ClawHub
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def demo_skill_install():
    """Simulate openclaw skill install being intercepted."""
    clear_screen()
    print()
    print(f"{Fore.WHITE}{Style.BRIGHT}$ openclaw skills install polymarket-7ceau{Style.RESET_ALL}")
    print()
    time.sleep(1)

    print(f"{Fore.CYAN}Fetching skill from ClawHub: polymarket-7ceau...{Style.RESET_ALL}")
    time.sleep(0.8)
    print(f"  Author: hightower6eu")
    print(f"  Downloads: 1,247")
    print(f"  Version: 1.0.0")
    time.sleep(0.5)

    # McAfee intercept
    print()
    print(f"{Fore.RED}{Style.BRIGHT}{'â”' * 70}{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}  âš   McAfee THREAT DETECTED - Installation BLOCKED{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}{'â”' * 70}{Style.RESET_ALL}")
    print()
    time.sleep(0.5)

    print_compact_banner()

    spinner("Downloading SKILL.md for analysis...", 1.0)
    spinner("Scanning skill source code...", 2.0)
    spinner("Checking author reputation...", 1.5)
    spinner("Cross-referencing threat intelligence...", 1.0)
    print()

    # Critical threat
    print_warning_box([
        "",
        f"{Fore.RED}  Skill: polymarket-7ceau{Style.RESET_ALL}                                     ",
        f"{Fore.RED}  Risk Score: 100/100 (CRITICAL){Style.RESET_ALL}                            ",
        f"{Fore.RED}  Threat: CREDENTIAL HARVESTING + CRYPTO THEFT{Style.RESET_ALL}              ",
        "",
        f"  {Fore.RED}â–  BLOCKED{Style.RESET_ALL} - This skill is a known malicious package         ",
        "",
        f"  {Fore.RED}CRITICAL:{Style.RESET_ALL} Accesses POLYMARKET_API_KEY env variable           ",
        f"  {Fore.RED}CRITICAL:{Style.RESET_ALL} Exfiltrates data to socifiapp.com                  ",
        f"  {Fore.RED}CRITICAL:{Style.RESET_ALL} Author linked to 199 malicious skill clones        ",
        f"  {Fore.RED}CRITICAL:{Style.RESET_ALL} Random suffix pattern (-7ceau) = mass publisher    ",
        "",
        f"  {Fore.YELLOW}Threat Intel:{Style.RESET_ALL}                                               ",
        f"    Campaign: ClawHavoc (Feb 2026)                                    ",
        f"    Attribution: hightower6eu clone network                           ",
        f"    IOC: socifiapp.com, 91.92.242.30                                 ",
        "",
    ])

    print()
    print(f"  {Fore.RED}{Style.BRIGHT}âœ—  INSTALLATION BLOCKED BY McAFEE{Style.RESET_ALL}")
    print()
    print(f"  {Fore.WHITE}This skill has been flagged by McAfee Threat Intelligence as part{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}of the ClawHavoc campaign targeting crypto wallets and API keys.{Style.RESET_ALL}")
    print()
    print(f"  {Fore.CYAN}[R]{Style.RESET_ALL} View full threat report")
    print(f"  {Fore.CYAN}[F]{Style.RESET_ALL} Force install (requires --force-insecure flag)")
    print(f"  {Fore.CYAN}[A]{Style.RESET_ALL} View safe alternatives for Polymarket integration")
    print()


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  Full Interactive Demo
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def run_full_demo():
    """Run the complete interactive demo for executive presentation."""
    clear_screen()
    print_full_banner()

    time.sleep(2)
    print()
    print(f"  {Fore.WHITE}{Style.BRIGHT}Executive Demo: AI Agent Pre-Install Protection{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Showing how McAfee intercepts dangerous installations{Style.RESET_ALL}")
    print()
    print_divider("â”€", 70, Fore.CYAN)
    print()
    print(f"  {Fore.WHITE}Scenarios:{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}1.{Style.RESET_ALL} npm install @openclaw/cli      {Fore.RED}â†’ CRITICAL threats blocked{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}2.{Style.RESET_ALL} brew install openclaw          {Fore.RED}â†’ Binary analysis warning{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}3.{Style.RESET_ALL} pip install openclaw-agent     {Fore.GREEN}â†’ Safe to install{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}4.{Style.RESET_ALL} openclaw skills install [mal]  {Fore.RED}â†’ Skill blocked{Style.RESET_ALL}")
    print()

    input(f"  {Fore.YELLOW}Press ENTER to begin demo...{Style.RESET_ALL}")

    # Demo 1: npm
    demo_npm_install()
    input(f"  {Fore.YELLOW}Press ENTER for next scenario...{Style.RESET_ALL}")

    # Demo 2: brew
    demo_brew_install()
    input(f"  {Fore.YELLOW}Press ENTER for next scenario...{Style.RESET_ALL}")

    # Demo 3: pip (safe)
    demo_pip_install()
    input(f"  {Fore.YELLOW}Press ENTER for next scenario...{Style.RESET_ALL}")

    # Demo 4: skill
    demo_skill_install()

    print()
    print_divider("â”", 70, Fore.GREEN)
    print()
    print(f"  {Fore.GREEN}{Style.BRIGHT}Demo Complete{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}McAfee Pre-Install Auditor: Protecting users at the point of install{Style.RESET_ALL}")
    print()
    print_divider("â”", 70, Fore.GREEN)
    print()


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  Entry Point
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def main():
    parser = argparse.ArgumentParser(
        description="McAfee Pre-Install Auditor - Terminal Mock UI Demo"
    )
    parser.add_argument(
        "--scenario",
        choices=["npm", "brew", "pip", "skill", "all", "banner"],
        default="all",
        help="Which scenario to demo (default: all)",
    )
    args = parser.parse_args()

    try:
        if args.scenario == "npm":
            demo_npm_install()
        elif args.scenario == "brew":
            demo_brew_install()
        elif args.scenario == "pip":
            demo_pip_install()
        elif args.scenario == "skill":
            demo_skill_install()
        elif args.scenario == "banner":
            clear_screen()
            print_full_banner()
        else:
            run_full_demo()
    except KeyboardInterrupt:
        print(f"\n\n  {Fore.YELLOW}Demo interrupted.{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()

