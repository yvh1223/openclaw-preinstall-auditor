#!/usr/bin/env python3
"""
McAfee OpenClaw Pre-Install Auditor - Clean Terminal UI (No Animations)
Shows clean output without progress bar animation artifacts.

Usage:
    python terminal_mock_ui_clean.py --scenario npm
    python terminal_mock_ui_clean.py --scenario brew
    python terminal_mock_ui_clean.py --scenario pip
    python terminal_mock_ui_clean.py --scenario skill
"""

import argparse
import sys
import time
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

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


MCAFEE_WORDMARK = f"""\
{Fore.RED}{Style.BRIGHT}  __  __   ____    _    {Fore.LIGHTRED_EX}_____  _____  _____{Style.RESET_ALL}
{Fore.RED}{Style.BRIGHT} |  \\/  | / ___|  / \\   {Fore.LIGHTRED_EX}|  ___|| ____|| ____|{Style.RESET_ALL}
{Fore.RED}{Style.BRIGHT} | |\\/| || |     / _ \\  {Fore.LIGHTRED_EX}| |_   |  _|  |  _|{Style.RESET_ALL}
{Fore.RED}{Style.BRIGHT} | |  | || |___ / ___ \\ {Fore.LIGHTRED_EX}|  _|  | |___ | |___{Style.RESET_ALL}
{Fore.RED}{Style.BRIGHT} |_|  |_| \\____/_/   \\_\\{Fore.LIGHTRED_EX}|_|    |_____||_____|{Style.RESET_ALL}"""


def print_banner():
    print()
    print(MCAFEE_WORDMARK)
    print()
    print(f"{Fore.RED}{Style.BRIGHT}    McAfee{Fore.WHITE} Pre-Install Security Auditor{Style.RESET_ALL}")
    print(f"{Fore.CYAN}    {'-' * 33}{Style.RESET_ALL}")
    print()


def print_divider():
    print(f"{Fore.YELLOW}{Style.BRIGHT}{'-' * 70}{Style.RESET_ALL}")


def demo_npm_install():
    """Clean npm install demo without animations."""
    print()
    print(f"{Fore.WHITE}{Style.BRIGHT}$ npm install -g @openclaw/cli{Style.RESET_ALL}")
    print()
    time.sleep(0.5)
    print(f"{Fore.WHITE}npm {Fore.CYAN}info{Style.RESET_ALL} it worked if it ends with ok")
    time.sleep(0.3)
    print(f"{Fore.WHITE}npm {Fore.CYAN}info{Style.RESET_ALL} using npm@10.2.4")
    print(f"{Fore.WHITE}npm {Fore.CYAN}info{Style.RESET_ALL} using node@v22.0.0")
    time.sleep(0.4)
    print(f"{Fore.WHITE}npm {Fore.CYAN}info{Style.RESET_ALL} resolving @openclaw/cli@latest")
    time.sleep(0.8)
    print()

    print_divider()
    print(f"{Fore.YELLOW}{Style.BRIGHT}  McAfee Pre-Install Auditor has intercepted this installation{Style.RESET_ALL}")
    print_divider()
    print()
    time.sleep(0.5)

    print_banner()
    time.sleep(0.3)

    # Show completed scans with dramatic delays
    print(f"  {Fore.YELLOW}Resolving package metadata...{Style.RESET_ALL}")
    time.sleep(1.2)
    print(f"  {Fore.GREEN}OK{Style.RESET_ALL} Resolved package metadata")

    print(f"  {Fore.YELLOW}Checking package registry signatures...{Style.RESET_ALL}")
    time.sleep(1.5)
    print(f"  {Fore.GREEN}OK{Style.RESET_ALL} Signatures verified")

    print(f"  {Fore.YELLOW}Scanning dependencies (247 packages)...{Style.RESET_ALL}")
    time.sleep(2.5)
    print(f"  {Fore.GREEN}OK{Style.RESET_ALL} Dependency scan complete")

    print(f"  {Fore.YELLOW}Analyzing postinstall scripts...{Style.RESET_ALL}")
    time.sleep(1.8)
    print(f"  {Fore.GREEN}OK{Style.RESET_ALL} Script analysis complete")

    print(f"  {Fore.YELLOW}Source code pattern analysis...{Style.RESET_ALL}")
    time.sleep(2.2)
    print(f"  {Fore.GREEN}OK{Style.RESET_ALL} Pattern analysis complete")

    print(f"  {Fore.YELLOW}Checking known vulnerability database...{Style.RESET_ALL}")
    time.sleep(1.5)
    print(f"  {Fore.RED}!{Style.RESET_ALL} {Fore.RED}Vulnerabilities detected!{Style.RESET_ALL}")

    print(f"  {Fore.YELLOW}Evaluating supply chain risk...{Style.RESET_ALL}")
    time.sleep(1.3)
    print(f"  {Fore.RED}!{Style.RESET_ALL} {Fore.RED}High-risk patterns identified!{Style.RESET_ALL}")

    print()
    time.sleep(0.5)

    # Clean warning box
    print(f"{Fore.RED}{Style.BRIGHT}+{'=' * 68}+{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Back.RED}{Fore.WHITE}{Style.BRIGHT}{' WARNING: SECURITY WARNING ':^68}{Style.RESET_ALL}{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}+{'=' * 68}+{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}                                                                     {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.RED}Package: @openclaw/cli@1.2.3{Style.RESET_ALL}                              {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.RED}Risk Score: 87/100 (CRITICAL){Style.RESET_ALL}                             {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}                                                                     {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.RED}*{Style.RESET_ALL} 3 Critical vulnerabilities found                      {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.YELLOW}*{Style.RESET_ALL} 7 High severity issues                                {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.YELLOW}*{Style.RESET_ALL} 12 Medium severity issues                             {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}                                                                     {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.RED}CRITICAL:{Style.RESET_ALL} CVE-2026-25253 - Token exfiltration via gateway {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.RED}CRITICAL:{Style.RESET_ALL} Postinstall script executes remote payload      {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.RED}CRITICAL:{Style.RESET_ALL} Accesses ~/.solana/id.json (crypto wallet)      {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}                                                                     {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.YELLOW}HIGH:{Style.RESET_ALL} 47 unpinned dependencies (supply chain risk)        {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.YELLOW}HIGH:{Style.RESET_ALL} Connects to known malicious IP: 91.92.242.30        {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.YELLOW}HIGH:{Style.RESET_ALL} Contains obfuscated eval() calls                    {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}                                                                     {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}+{'=' * 68}+{Style.RESET_ALL}")
    print()

    print(f"  {Fore.RED}{Style.BRIGHT}!  RECOMMENDATION: DO NOT INSTALL{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}This package contains known security threats that could{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}compromise your system credentials and crypto wallets.{Style.RESET_ALL}")
    print()
    print(f"  {Fore.CYAN}[V]{Style.RESET_ALL} View full report    {Fore.CYAN}[I]{Style.RESET_ALL} Install anyway    {Fore.CYAN}[C]{Style.RESET_ALL} Cancel installation")
    print(f"  {Fore.CYAN}[R]{Style.RESET_ALL} Report to McAfee    {Fore.CYAN}[S]{Style.RESET_ALL} Safe alternative")
    print()


def demo_brew_install():
    """Clean brew install demo."""
    print()
    print(f"{Fore.WHITE}{Style.BRIGHT}$ brew install openclaw{Style.RESET_ALL}")
    print()
    time.sleep(0.5)
    print(f"{Fore.GREEN}==>{Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT} Downloading https://github.com/openclaw/openclaw/releases/v1.2.3{Style.RESET_ALL}")
    time.sleep(0.6)
    print(f"{Fore.GREEN}==>{Style.RESET_ALL} Downloading from https://objects.githubusercontent.com/...")
    time.sleep(0.8)
    print(f"######################################################################## 100.0%")
    time.sleep(0.3)
    print()

    print_divider()
    print(f"{Fore.YELLOW}{Style.BRIGHT}  McAfee Pre-Install Auditor: Scanning before installation...{Style.RESET_ALL}")
    print_divider()
    print()
    time.sleep(0.5)

    print_banner()
    time.sleep(0.3)

    print(f"  {Fore.YELLOW}Verifying code signature...{Style.RESET_ALL}")
    time.sleep(1.5)
    print(f"  {Fore.GREEN}OK{Style.RESET_ALL} Signature verified")

    print(f"  {Fore.YELLOW}Checking binary hash against threat database...{Style.RESET_ALL}")
    time.sleep(1.8)
    print(f"  {Fore.RED}!{Style.RESET_ALL} {Fore.RED}Threat signatures detected!{Style.RESET_ALL}")

    print(f"  {Fore.YELLOW}Analyzing bundled dependencies...{Style.RESET_ALL}")
    time.sleep(2.0)
    print(f"  {Fore.GREEN}OK{Style.RESET_ALL} Dependencies analyzed")

    print(f"  {Fore.YELLOW}Scanning for known CVEs...{Style.RESET_ALL}")
    time.sleep(1.7)
    print(f"  {Fore.RED}!{Style.RESET_ALL} {Fore.RED}Critical CVEs found!{Style.RESET_ALL}")

    print(f"  {Fore.YELLOW}Checking network behavior patterns...{Style.RESET_ALL}")
    time.sleep(1.4)
    print(f"  {Fore.RED}!{Style.RESET_ALL} {Fore.RED}Suspicious network activity detected!{Style.RESET_ALL}")

    print(f"  {Fore.YELLOW}Runtime behavior prediction...{Style.RESET_ALL}")
    time.sleep(1.6)
    print(f"  {Fore.GREEN}OK{Style.RESET_ALL} Analysis complete")

    print()
    time.sleep(0.5)

    # Warning box
    print(f"{Fore.RED}{Style.BRIGHT}+{'=' * 68}+{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Back.RED}{Fore.WHITE}{Style.BRIGHT}{'\!   SECURITY WARNING  \!':^68}{Style.RESET_ALL}{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}+{'=' * 68}+{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}                                                                     {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.RED}Package: openclaw v1.2.3 (Homebrew){Style.RESET_ALL}                          {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.RED}Risk Score: 92/100 (CRITICAL){Style.RESET_ALL}                              {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}                                                                     {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.RED}*{Style.RESET_ALL} 5 Critical findings    {Fore.YELLOW}*{Style.RESET_ALL} 8 High    * 15 Medium       {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}                                                                     {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.RED}CRITICAL:{Style.RESET_ALL} Binary connects to C2 server on first run          {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.RED}CRITICAL:{Style.RESET_ALL} Requests full disk access via entitlements          {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.RED}CRITICAL:{Style.RESET_ALL} postinstall hooks execute unsigned scripts          {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.RED}CRITICAL:{Style.RESET_ALL} Known CVE-2026-25253 (auth bypass)                 {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.RED}CRITICAL:{Style.RESET_ALL} Disables macOS Gatekeeper (xattr -c)               {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}                                                                     {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.YELLOW}HIGH:{Style.RESET_ALL} WebSocket allows localhost CSWSH attacks              {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.YELLOW}HIGH:{Style.RESET_ALL} Default config exposes admin API on 0.0.0.0           {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}                                                                     {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}+{'=' * 68}+{Style.RESET_ALL}")
    print()

    print(f"  {Fore.RED}{Style.BRIGHT}\!  DO NOT INSTALL - CRITICAL THREATS DETECTED{Style.RESET_ALL}")
    print()
    print(f"  {Fore.CYAN}[V]{Style.RESET_ALL} View full report    {Fore.CYAN}[I]{Style.RESET_ALL} Install anyway    {Fore.CYAN}[C]{Style.RESET_ALL} Cancel installation")
    print()


def demo_pip_install():
    """Clean pip install demo (safe package)."""
    print()
    print(f"{Fore.WHITE}{Style.BRIGHT}$ pip install openclaw-agent{Style.RESET_ALL}")
    print()
    time.sleep(0.4)
    print(f"Collecting openclaw-agent")
    time.sleep(0.5)
    print(f"  Downloading openclaw_agent-0.8.1-py3-none-any.whl (2.4 MB)")
    time.sleep(0.7)
    print(f"     ---------------------------------------- 2.4/2.4 MB 12.3 MB/s")
    time.sleep(0.3)
    print()

    print_divider()
    print(f"{Fore.YELLOW}{Style.BRIGHT}  McAfee Pre-Install Auditor: Scanning Python package...{Style.RESET_ALL}")
    print_divider()
    print()
    time.sleep(0.5)

    print_banner()
    time.sleep(0.3)

    print(f"  {Fore.YELLOW}Inspecting setup.py / pyproject.toml...{Style.RESET_ALL}")
    time.sleep(1.2)
    print(f"  {Fore.GREEN}OK{Style.RESET_ALL} Package metadata verified")

    print(f"  {Fore.YELLOW}Checking PyPI package integrity...{Style.RESET_ALL}")
    time.sleep(1.5)
    print(f"  {Fore.GREEN}OK{Style.RESET_ALL} Package integrity confirmed")

    print(f"  {Fore.YELLOW}Scanning package source code...{Style.RESET_ALL}")
    time.sleep(2.0)
    print(f"  {Fore.GREEN}OK{Style.RESET_ALL} No malicious patterns detected")

    print(f"  {Fore.YELLOW}Analyzing dependency tree (34 packages)...{Style.RESET_ALL}")
    time.sleep(1.8)
    print(f"  {Fore.GREEN}OK{Style.RESET_ALL} Dependencies analyzed")

    print(f"  {Fore.YELLOW}Checking for typosquatting indicators...{Style.RESET_ALL}")
    time.sleep(1.3)
    print(f"  {Fore.GREEN}OK{Style.RESET_ALL} Package name verified")

    print()
    time.sleep(0.5)

    # Safe box
    print(f"{Fore.GREEN}{Style.BRIGHT}+{'=' * 68}+{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{Style.BRIGHT}|{Back.GREEN}{Fore.WHITE}{Style.BRIGHT}{'OK  SCAN COMPLETE - LOW RISK  OK':^68}{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{Style.BRIGHT}+{'=' * 68}+{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}                                                                     {Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}   Package: openclaw-agent v0.8.1 (PyPI)                               {Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}   Risk Score: {Fore.GREEN}18/100 (LOW){Style.RESET_ALL}                                         {Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}                                                                     {Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.GREEN}OK{Style.RESET_ALL} No critical vulnerabilities found                           {Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.GREEN}OK{Style.RESET_ALL} Package signature verified                                  {Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.GREEN}OK{Style.RESET_ALL} No suspicious postinstall scripts                           {Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.GREEN}OK{Style.RESET_ALL} No credential harvesting patterns                           {Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}                                                                     {Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.YELLOW}NOTICE:{Style.RESET_ALL} 2 medium-severity findings:                            {Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}     - urllib3 < 2.0.7 has known CVE (update recommended)               {Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}     - 3 unpinned transitive dependencies                               {Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}                                                                     {Fore.GREEN}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{Style.BRIGHT}+{'=' * 68}+{Style.RESET_ALL}")
    print()

    print(f"  {Fore.GREEN}{Style.BRIGHT}OK  SAFE TO INSTALL{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}  Proceeding with installation...{Style.RESET_ALL}")
    print()
    print(f"Installing collected packages: openclaw-agent")
    print(f"Successfully installed openclaw-agent-0.8.1")
    print()
    print(f"  {Fore.CYAN}McAfee runtime protection: ENABLED{Style.RESET_ALL}")
    print()


def demo_skill_install():
    """Clean skill install demo (malicious)."""
    print()
    print(f"{Fore.WHITE}{Style.BRIGHT}$ openclaw skills install polymarket-7ceau{Style.RESET_ALL}")
    print()
    time.sleep(0.5)
    print(f"{Fore.CYAN}Fetching skill from ClawHub: polymarket-7ceau...{Style.RESET_ALL}")
    time.sleep(0.8)
    print(f"  Author: hightower6eu")
    print(f"  Downloads: 1,247")
    print(f"  Version: 1.0.0")
    time.sleep(0.6)
    print()

    print(f"{Fore.RED}{Style.BRIGHT}{'-' * 70}{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}  \!  McAfee THREAT DETECTED - Installation BLOCKED{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}{'-' * 70}{Style.RESET_ALL}")
    print()
    time.sleep(0.5)

    print_banner()
    time.sleep(0.3)

    print(f"  {Fore.YELLOW}Downloading SKILL.md for analysis...{Style.RESET_ALL}")
    time.sleep(1.0)
    print(f"  {Fore.GREEN}OK{Style.RESET_ALL} Skill manifest downloaded")

    print(f"  {Fore.YELLOW}Scanning skill source code...{Style.RESET_ALL}")
    time.sleep(1.5)
    print(f"  {Fore.RED}!{Style.RESET_ALL} {Fore.RED}Malicious code detected!{Style.RESET_ALL}")

    print(f"  {Fore.YELLOW}Checking author reputation...{Style.RESET_ALL}")
    time.sleep(1.8)
    print(f"  {Fore.RED}!{Style.RESET_ALL} {Fore.RED}Author flagged for malicious activity!{Style.RESET_ALL}")

    print(f"  {Fore.YELLOW}Cross-referencing threat intelligence...{Style.RESET_ALL}")
    time.sleep(2.0)
    print(f"  {Fore.RED}!{Style.RESET_ALL} {Fore.RED}Matched known threat campaign!{Style.RESET_ALL}")

    print()
    time.sleep(0.7)

    # Critical threat box
    print(f"{Fore.RED}{Style.BRIGHT}+{'=' * 68}+{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Back.RED}{Fore.WHITE}{Style.BRIGHT}{'\!   CRITICAL THREAT DETECTED   \!':^68}{Style.RESET_ALL}{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}+{'=' * 68}+{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}                                                                     {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.RED}Skill: polymarket-7ceau{Style.RESET_ALL}                                      {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.RED}Risk Score: 100/100 (CRITICAL){Style.RESET_ALL}                             {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.RED}Threat: CREDENTIAL HARVESTING + CRYPTO THEFT{Style.RESET_ALL}               {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}                                                                     {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.RED}* BLOCKED{Style.RESET_ALL} - This skill is a known malicious package          {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}                                                                     {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.RED}CRITICAL:{Style.RESET_ALL} Accesses POLYMARKET_API_KEY env variable            {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.RED}CRITICAL:{Style.RESET_ALL} Exfiltrates data to socifiapp.com                   {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.RED}CRITICAL:{Style.RESET_ALL} Author linked to 199 malicious skill clones         {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.RED}CRITICAL:{Style.RESET_ALL} Random suffix pattern (-7ceau) = mass publisher     {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}                                                                     {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.YELLOW}Threat Intel:{Style.RESET_ALL}                                                {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}     Campaign: ClawHavoc (Feb 2026)                                     {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}     Attribution: hightower6eu clone network                            {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}     IOC: socifiapp.com, 91.92.242.30                                  {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}                                                                     {Fore.RED}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}+{'=' * 68}+{Style.RESET_ALL}")
    print()

    print(f"  {Fore.RED}{Style.BRIGHT}X  INSTALLATION BLOCKED BY McAFEE{Style.RESET_ALL}")
    print()
    print(f"  {Fore.WHITE}This skill has been flagged by McAfee Threat Intelligence as part{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}of the ClawHavoc campaign targeting crypto wallets and API keys.{Style.RESET_ALL}")
    print()
    print(f"  {Fore.CYAN}[R]{Style.RESET_ALL} View full threat report")
    print(f"  {Fore.CYAN}[F]{Style.RESET_ALL} Force install (requires --force-insecure flag)")
    print(f"  {Fore.CYAN}[A]{Style.RESET_ALL} View safe alternatives for Polymarket integration")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="McAfee Pre-Install Auditor - Clean Terminal UI (No Animations)"
    )
    parser.add_argument(
        "--scenario",
        choices=["npm", "brew", "pip", "skill"],
        default="npm",
        help="Which scenario to demo (default: npm)",
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
    except KeyboardInterrupt:
        print(f"\n\n  {Fore.YELLOW}Demo interrupted.{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()