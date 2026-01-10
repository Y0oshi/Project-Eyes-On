#!/usr/bin/env python3
# ----------------------------------------------------------------------------------
# Coded by: Y0oshi (IG: @rde0)
# Project: Project Eyes On
# Description: Custom surveillance tool for scanning public IP cameras.
# ----------------------------------------------------------------------------------

import requests
import time
import random
import json
import sys
import threading
import concurrent.futures
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# --- CONFIGURATION ---
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
]

INSECAM_BASE = "http://www.insecam.org/en"

BANNER = """
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣶⣿⠿⠛⠛⠛⠻⠿⣿⣿⣿⣿⣿⣶⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣷⣻⠶⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⠂⠀⢀⣠⣾⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⢀⣤⣾⣿⣿⣿⣿⣿⣿⡿⣽⣻⣳⢎⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⢡⠂⠄⣢⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⡷⣯⡞⣝⢆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠁⡐⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣳⣟⡾⣹⢎⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠂⣼⣿⣿⣿⣿⡿⠿⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠻⠿⣿⣿⣿⣿⣿⡿⣾⣝⣧⢻⡜⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢂⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠂⢸⣿⡿⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠻⠿⣿⣳⢯⣞⡳⣎⠅⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⢈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⠁⠚⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠛⢯⡞⣵⣋⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠱⣍⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡞⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡄⢀⣾⡇⠀⣾⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁⣾⣿⡇⢰⣿⣿⠀⠀⣆⠀⠀⠀⠀⢰⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⣼⡏⢰⣿⣿⠇⣾⣿⣿⡆⠀⣿⠀⠀⠀⠀⢸⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⡇⠀⠀⠀⠀⠀⠀⠀⠀⠰⠃⠀⠒⠛⠃⠚⠿⣿⢰⣿⣿⣿⡇⣤⣿⣤⣶⣦⣀⢼⣿⣧⠀⢰⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⢠⣶⢰⣿⣿⣿⣧⡹⢓⣾⣾⣿⣿⣿⣧⣿⣿⣿⣿⣋⣁⣀⣀⣀⣁⠘⠃⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣾⡟⢋⠁⡀⠀⠉⠙⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠱⣚⣭⡿⢿⣿⣷⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡄⢠⣆⠀⠀⠀⠀⣿⣏⡀⣾⠀⠀⠀⠀⣰⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⣁⠀⢠⠀⠀⠉⠻⢿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⢇⣾⣿⣷⠀⠀⠀⣿⣏⡓⠥⠬⣒⣷⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⠀⠀⠀⠀⠀⣦⠈⢳⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣾⣿⣿⣿⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣮⡢⢄⡀⠤⠾⢧⣦⣼⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⡇⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢟⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣶⣶⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⢁⣿⣿⠇⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣏⢾⡅⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠆⣼⣿⣿⣦⣾⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣷⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠀⠀⠀⢀⠰⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣻⢿⣯⡿⣟⠇⠀⡜⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⠀⠀⠀⠀⠀⠌⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⢧⡟⡿⣾⡽⢏⣿⣾⣿⡌⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣛⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⡰⣣⢻⡜⣯⢳⡝⣼⣿⣿⣿⣿⣆⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⢂⠐⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⠎⡵⢣⢧⡹⣜⢣⣿⣿⣿⣿⣿⣿⣿⣷⡌⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⢀⠂⠔⡀⢂⠐⡀⢂⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠡⢚⠴⣉⠦⡑⢎⢣⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⣙⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⡩⠂⠀⠀⠀⠀⠀⣀⡔⢦⠃⢈⠐⡀⢂⠐⠠⠀⠄⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠁⠎⡰⢡⠙⡌⣸⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠟⠒⠌⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠉⠀⠈⠀⠀⠀⠀⠀⣀⠶⡱⢎⢧⢋⠀⡐⢀⠂⠌⢀⠂⢀⠂⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠢⠑⡨⣟⠿⠟⠟⠋⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠛⠟⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢴⡩⢞⡱⢫⠜⡪⢅⠀⠂⠄⠂⠠⠀⠂⢀⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢢⡙⢦⡙⡔⢣⠈⢀⠂⠈⡀⠐⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠂⠴⢉⠆⡁⠀⡀⠁⢀⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠐⠡⠀⠀⠐⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                     OPERATION EYES ON
"""

# Global State
FOUND_CAMS = []
FILTER_MODE = "ALL"  # ALL, STREAM, SNAPSHOT

class InsecamScraper:
    def get_url(self, country=None, page=1):
        if country:
            return f"{INSECAM_BASE}/bycountry/{country}/?page={page}"
        return f"{INSECAM_BASE}/byrating/?page={page}"

    def scrape_page(self, url, page_num):
        targets = []
        try:
            # Emulate real user navigation
            headers = {
                'User-Agent': random.choice(USER_AGENTS),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Referer': 'https://www.google.com/',
                'DNT': '1', # Do Not Track request
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            res = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if res.status_code == 200:
                soup = BeautifulSoup(res.text, 'html.parser')
                for img in soup.find_all('img'):
                    src = img.get('src')
                    title = img.get('title', '')
                    
                    if src and "http" in src:
                        if "static" not in src and "insecam" not in src:
                            # Parse Title for identifying info
                            # Format usually: "Live camera [BRAND] in [CITY], [COUNTRY]"
                            brand = "Generic"
                            location = "Unknown"
                            
                            try:
                                if " in " in title:
                                    parts = title.split(" in ")
                                    pre_brand = parts[0]
                                    if "Live camera " in pre_brand:
                                        brand_candidate = pre_brand.replace("Live camera ", "").strip()
                                        if brand_candidate:
                                            brand = brand_candidate.strip()
                                    
                                    location = parts[1].strip()
                            except:
                                pass
                                
                            targets.append({
                                "url": src,
                                "brand": brand,
                                "location": location
                            })
                return targets
            else:
                return []
        except Exception:
            return []

    def mass_scrape(self, country=None, max_pages=5):
        all_targets = []
        print(f"{Fore.CYAN}[*] Spinning up Insecam Scraper (Threads: 10, Depth: {max_pages})...")
        
        # We use a set for instant deduplication during the scrape phase
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for i in range(1, max_pages + 1):
                url = self.get_url(country, i)
                futures.append(executor.submit(self.scrape_page, url, i))
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    targets = future.result()
                    all_targets.extend(targets)
                    sys.stdout.write(f"\r{Fore.GREEN}[+] Scraping Insecam: {len(all_targets)} potential feeds found...")
                    sys.stdout.flush()
                except:
                    pass
                    
        # Clean up duplicates
        unique_targets = {}
        for t in all_targets:
            unique_targets[t['url']] = t
            
        print(f"\n{Fore.GREEN}[+] Insecam Scrape Done. Unique Feeds: {len(unique_targets)}")
        return list(unique_targets.values())

class DorkScraper:
    # google/yahoo dorking logic
    DORKS = [
        'inurl:"/view/index.shtml"',
        'inurl:"/view/view.shtml"',
        'intitle:"Live View / - AXIS"',
        'inurl:"/CgiStart?page=Single"',
        'intitle:"WVC80N"',
        'intitle:"Network Camera NetworkCamera"',
        'inurl:top.htm inurl:currenttime',
        'intitle:"ip camera" "view"',
        'inurl:"/mjpg/video.mjpg"'
    ]

    def search_yahoo(self, query, limit=50):
        """Fallback to Yahoo Search with Pagination"""
        # print(f"{Fore.YELLOW}        [~] Google blocked. Falling back to Yahoo...")
        targets = []
        start = 1
        page_count = 0
        
        while len(targets) < limit:
            # Aggressive Speed: Minimal delay
            time.sleep(random.uniform(0.5, 1.0))
            page_count += 1
            
            headers = {
                'User-Agent': random.choice(USER_AGENTS),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            }

            # ... (rest of search_yahoo logic stays similar, just showing the delay change) ....
            try:
                url = f"https://search.yahoo.com/search?p={query}&b={start}"
                res = requests.get(url, headers=headers, timeout=5) # Reduced timeout
                
                if res.status_code == 200:
                    soup = BeautifulSoup(res.text, 'html.parser')
                    results = soup.find_all('div', class_='algo')
                    
                    if not results:
                        break
                        
                    import urllib.parse
                    new_found = 0
                    
                    for div in results:
                        a = div.find('a')
                        if a:
                            raw_link = a.get('href')
                            real_url = raw_link
                            if "/RU=" in raw_link:
                                try:
                                    start_token = raw_link.find("/RU=") + 4
                                    end_token = raw_link.find("/", start_token)
                                    if end_token == -1: end_token = len(raw_link)
                                    extracted = raw_link[start_token:end_token]
                                    real_url = urllib.parse.unquote(extracted)
                                except:
                                    pass
                                    
                            if real_url and "http" in real_url and "yahoo.com" not in real_url:
                                targets.append({
                                    "url": real_url,
                                    "brand": "Yahoo Result",
                                    "location": "Unknown"
                                })
                                new_found += 1
                                if len(targets) >= limit: break
                    
                    # Progress Feedback
                    sys.stdout.write(f"\r{Fore.YELLOW}        [~] Yahoo Page {page_count}: Found {new_found} (Total: {len(targets)}/{limit})...")
                    sys.stdout.flush()
                    
                    start += 10
                else:
                     break
            except Exception:
                break
            
        print() # Newline after loop
        return targets

    def process_dork(self, dork, limit):
        """Worker function for a single dork"""
        dork_targets = []
        
        # Check for google lib local import to handle thread safety if needed
        has_google = False
        try:
            from googlesearch import search
            has_google = True
        except ImportError:
            pass

        print(f"{Fore.YELLOW}    [>] Searching...")
        
        if has_google:
            try:
                count = 0
                for url in search(dork, num_results=limit, lang="en"):
                        dork_targets.append({
                        "url": url,
                        "brand": "Google Result",
                        "location": "Unknown"
                        })
                        count += 1
                        if count >= limit: break 
            except Exception as e:
                # Silently failover
                dork_targets = self.search_yahoo(dork, limit=limit)
        else:
            dork_targets = self.search_yahoo(dork, limit=limit)
            
        return dork_targets

    def scan(self, limit=50):
        print(f"{Fore.CYAN}[*] Engaging Google Dorks (Deep Web Search - Limit: {limit})...")
        print(f"{Fore.CYAN}[*] Spinning up {len(self.DORKS)} concurrent search threads (MAX SPEED)...")
        
        all_targets = []
        
        # Run ALL dorks in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.DORKS)) as executor:
            future_to_dork = {executor.submit(self.process_dork, dork, limit): dork for dork in self.DORKS}
            
            for future in concurrent.futures.as_completed(future_to_dork):
                try:
                    results = future.result()
                    all_targets.extend(results)
                except Exception as e:
                    pass

        return all_targets

class Verifier:
    def verify(self, target):
        # ... (Verification logic unchanged) ...
        # Target is now a dict {url, brand, location}
        url = target['url']
        try:
            # Fast verification
            res = requests.get(url, timeout=3, stream=True, headers={'User-Agent': random.choice(USER_AGENTS)}, verify=False)
            
            if res.status_code == 200:
                ct = res.headers.get("Content-Type", "").lower()
                server = res.headers.get("Server", "Unknown")
                
                cam_type = "Unknown"
                if "multipart" in ct or "x-mixed-replace" in ct:
                    cam_type = "LIVE STREAM (MJPEG)"
                elif "image" in ct:
                    cam_type = "SNAPSHOT (JPEG)"
                elif "video" in ct:
                    cam_type = "VIDEO FEED"
                
                if cam_type != "Unknown":
                    # Filter Logic
                    if FILTER_MODE == "STREAM" and "STREAM" not in cam_type:
                        return None
                    if FILTER_MODE == "SNAPSHOT" and "SNAPSHOT" not in cam_type:
                        return None
                        
                    return {
                        "url": url,
                        "status": "Live",
                        "type": cam_type,
                        "server": server,
                        "brand": target['brand'],
                        "location": target['location']
                    }
        except:
            pass
        return None

def center_print(text, width=120, color=Fore.WHITE, end="\n"):
    clean_text = text.replace(Fore.RED, "").replace(Fore.WHITE, "").replace(Fore.CYAN, "").replace(Fore.YELLOW, "").replace(Fore.GREEN, "").replace(Fore.BLUE, "").replace(Style.BRIGHT, "").replace(Style.RESET_ALL, "")
    padding = max(0, (width - len(clean_text)) // 2)
    print(" " * padding + color + text, end=end)

def print_banner():
    # Split banner, strip hardcoded left padding, then center
    lines = BANNER.strip().split("\n")
    print(Fore.RED, end="")
    for line in lines:
        center_print(line.strip(), color=Fore.RED)
        
    center_print("v3.0 | GLOBAL SURVEILLANCE | UNIFIED INTELLIGENCE", color=Style.BRIGHT + Fore.WHITE)
    center_print("Made by Y0oshi | IG: @rde0", color=Style.BRIGHT + Fore.YELLOW)
    center_print("-" * 80, color=Fore.WHITE)

def run_operation(country=None, pages=3, mode="UNIFIED"):
    scraper = InsecamScraper()
    verifier = Verifier()
    dorker = DorkScraper()
    
    targets = []
    
    # 1. SCRAPE PHASE (SILENT UNIFIED)
    center_print(f"=== INITIALIZING GLOBAL SURVEILLANCE SCAN ===", color=Style.BRIGHT + Fore.YELLOW)
    print()
    
    if mode in ["UNIFIED", "INSECAM"]:
        # Increase Insecam threads
        found = scraper.mass_scrape(country=country, max_pages=pages)
        targets.extend(found)

    if mode in ["UNIFIED", "DORK"]:
        # Convert pages to approximate limit (10 results per page approx)
        dork_limit = pages * 10
        found = dorker.scan(limit=dork_limit)
        targets.extend(found)

    # Deduplicate
    unique_targets = {t['url']: t for t in targets}
    targets = list(unique_targets.values())
    
    center_print(f"[*] Aggregated {len(targets)} unique targets.", color=Fore.CYAN)
    print()
    
    # 2. VERIFY PHASE
    center_print(f"=== VERIFYING FEEDS ({FILTER_MODE}) ===", color=Style.BRIGHT + Fore.YELLOW)
    print()
    
    valid_count = 0
    # Increase Verifier Threads to 100
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        if not targets:
            center_print("[-] No targets found.", color=Fore.RED)
            return

        futures = {executor.submit(verifier.verify, t): t for t in targets}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                color = Fore.GREEN if "STREAM" in res['type'] else Fore.CYAN
                # Display Brand and Location (Simplified)
                brand_display = res['brand']
                if brand_display in ["Dork Result", "Google Result", "DDG Result", "Generic", "Yahoo Result"]:
                     brand_display = "IP Camera" # Generic display for seamless look
                     
                print(f"{color}[+] {Fore.WHITE}{res['url']} {Fore.MAGENTA}({brand_display} | {res['location']})")
                FOUND_CAMS.append(res)
                valid_count += 1
    
    print()
    center_print(f"Total Valid Cameras: {valid_count}", color=Style.BRIGHT + Fore.GREEN)
    
    # Save
    filename = f"scan_result_{int(time.time())}.json"
    with open(filename, 'w') as f:
        json.dump(FOUND_CAMS, f, indent=4)
    center_print(f"Report saved to {filename}", color=Fore.BLUE)

def resize_terminal(rows=50, cols=120):
    sys.stdout.write(f"\x1b[8;{rows};{cols}t")
    sys.stdout.flush()

# Country Database (Top 20 by volume for brevity in code, but supports all)
COUNTRIES = {
    "US": "United States (543)", "JP": "Japan (368)", "IT": "Italy (145)", "DE": "Germany (124)",
    "RU": "Russia (72)", "AT": "Austria (69)", "FR": "France (65)", "CZ": "Czech Republic (55)",
    "KR": "Korea (50)", "RO": "Romania (39)", "TW": "Taiwan (38)", "CH": "Switzerland (38)",
    "NO": "Norway (35)", "CA": "Canada (35)", "PL": "Poland (27)", "NL": "Netherlands (26)",
    "SE": "Sweden (25)", "GB": "United Kingdom (22)", "ES": "Spain (21)", "BG": "Bulgaria (16)",
    "RS": "Serbia (14)", "DK": "Denmark (13)", "UA": "Ukraine (11)", "BE": "Belgium (9)",
    "SK": "Slovakia (8)", "ZA": "South Africa (7)", "TR": "Turkey (7)", "FI": "Finland (7)",
    "IN": "India (7)", "HU": "Hungary (7)", "ID": "Indonesia (6)", "GR": "Greece (6)",
    "IE": "Ireland (5)", "TH": "Thailand (5)", "HK": "Hong Kong (4)", "BR": "Brazil (4)",
    "AR": "Argentina (4)", "EG": "Egypt (4)", "IL": "Israel (4)", "NZ": "New Zealand (4)"
}

def main():
    global FILTER_MODE
    resize_terminal()
    requests.packages.urllib3.disable_warnings()
    print_banner()
    
    print(f"{Fore.WHITE}Commands:")
    print(f"  {Fore.CYAN}/scan               {Fore.WHITE}- Start Global Scan")
    print(f"  {Fore.CYAN}/country [code]     {Fore.WHITE}- Target Specific Country")
    print(f"  {Fore.CYAN}/mode [type]        {Fore.WHITE}- Set filter: ALL, STREAM, SNAPSHOT")
    print(f"  {Fore.CYAN}/exit               {Fore.WHITE}- Quit")
    
    while True:
        try:
            # For header input, we might want to keep it simple left or find a way to center prompt
            # Centering prompt is awkward. Let's keep prompt left for functional typing.
            cmd_raw = input(f"\n{Fore.RED}eyes-on ({FILTER_MODE})>{Fore.WHITE} ").strip()
            if not cmd_raw: continue
            
            parts = cmd_raw.split()
            cmd = parts[0].lower()
            
            if cmd == "/scan":
                pages = 3
                if len(parts) > 1 and parts[1].isdigit():
                     pages = int(parts[1])
                run_operation(mode="UNIFIED", pages=pages)
                
            elif cmd == "/country":
                if len(parts) < 2:
                    print(f"{Fore.RED}[!] Usage: /country [CODE]")
                    continue
                code = parts[1].upper()
                run_operation(country=code, mode="INSECAM", pages=5)
            
            # Legacy commands hidden for cleanliness
            elif cmd == "/dork":
                run_operation(mode="DORK")

            elif cmd == "/countries":
                center_print("=== AVAILABLE COUNTRIES ===", color=Fore.YELLOW)
                sorted_countries = sorted(COUNTRIES.items(), key=lambda x: x[0])
                count = 0
                for code, name in sorted_countries:
                    print(f"{Fore.CYAN}{code:<4} {Fore.WHITE}{name:<30}", end="")
                    count += 1
                    if count % 3 == 0:
                        print()
                print(f"\n{Fore.GREEN}[*] Use /country [CODE] to target.")
                
            elif cmd == "/mode":
                if len(parts) < 2:
                    print(f"{Fore.YELLOW}[*] Current Mode: {FILTER_MODE}")
                    continue
                mode = parts[1].upper()
                if mode in ["ALL", "STREAM", "SNAPSHOT"]:
                    FILTER_MODE = mode
                    print(f"{Fore.GREEN}[+] Filter set to {FILTER_MODE}")
                else:
                    print(f"{Fore.RED}[-] Invalid mode. Use ALL, STREAM, or SNAPSHOT")
            
            elif cmd == "/clear":
                print("\033[H\033[J", end="")
                print_banner()

            elif cmd == "/exit":
                sys.exit(0)
                
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}Aborted.")
            break

if __name__ == "__main__":
    main()
