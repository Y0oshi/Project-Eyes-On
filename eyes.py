#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  OPERATION EYES ON v3.0                                                       ║
║  Public IP Camera Reconnaissance Tool                                        ║
║  Coded by: Y0oshi | IG: @rde0                                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

A surveillance tool for discovering publicly accessible IP cameras using:
  - Insecam directory scraping
  - Multi-engine dorking (Yahoo + Startpage)
  - GeoIP location enrichment
  - Live stream verification

For educational and authorized security research purposes only.
"""

import requests
import time
import random
import json
import sys
import concurrent.futures
from urllib.parse import urlparse, unquote
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

init(autoreset=True)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1"
]

INSECAM_BASE = "http://www.insecam.org/en"

# Camera discovery dorks - organized by manufacturer
CAMERA_DORKS = [
    # Axis Communications
    'inurl:"/view/index.shtml"',
    'inurl:"/view/view.shtml"',
    'intitle:"Live View / - AXIS"',
    'inurl:axis-cgi/jpg',
    'inurl:axis-cgi/mjpg',
    'intitle:"AXIS 240 Camera Server"',
    
    # Hikvision
    'intitle:"Hikvision Web Cameras"',
    'inurl:"/doc/page/login.asp" intext:"Hikvision"',
    'intitle:"Hikvision" inurl:"login.asp"',
    
    # Mobotix
    'inurl:"/cgi-bin/guestimage.html"',
    'inurl:"/control/faststream.jpg"',
    'intitle:"MOBOTIX" inurl:"/control/userimage.html"',
    
    # Foscam
    'intitle:"Foscam" inurl:"login.htm"',
    'inurl:"/videostream.cgi?user="',
    
    # Panasonic
    'inurl:"/CgiStart?page=Single"',
    'intitle:"Panasonic Network Camera"',
    'inurl:"/nphMotionJpeg?Resolution="',
    
    # D-Link
    'intitle:"D-Link" inurl:"/video.htm"',
    'inurl:"/mjpg/video.cgi" intitle:"D-Link"',
    'intitle:"D-Link DCS-"',
    
    # Sony
    'intitle:"sony network camera snc-pl"',
    'intitle:"Sony" inurl:"/home/homeJ.html"',
    
    # Generic MJPEG streams
    'inurl:"/mjpg/video.mjpg"',
    'inurl:"/axis-cgi/mjpg"',
    'intitle:"webcamXP- 5"',
]

BANNER = """
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣶⣿⠿⠛⠛⠛⠻⠿⣿⣿⣿⣿⣿⣶⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣷⣻⠶⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⠂⠀⢀⣠⣾⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⢀⣤⣾⣿⣿⣿⣿⣿⣿⡿⣽⣻⣳⢎⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⢡⠂⠄⣢⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⡷⣯⡞⣝⢆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠁⡐⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣳⣟⡾⣹⢎⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠂⣼⣿⣿⣿⣿⡿⠿⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠻⠿⣿⣿⣿⣿⣿⡿⣾⣝⣧⢻⡜⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢂⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠂⢸⣿⡿⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠻⠿⣿⣳⢯⣞⡳⣎⠅⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⢈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
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
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣾⣿⣿⣿⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢟⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣮⡢⢄⡀⠤⠾⢧⣦⣼⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⡇⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣏⢾⡅⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣶⣶⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⢁⣿⣿⠇⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣏⢾⡅⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠆⣼⣿⣿⣦⣾⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣷⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠀⠀⠀⢀⠰⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣻⢿⣯⡿⣟⠇⠀⡜⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⠀⠀⠀⠀⠀⠌⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⢧⡟⡿⣾⡽⢏⣿⣾⣿⡌⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣛⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⡰⣣⢻⡜⣯⢳⡝⣼⣿⣿⣿⣿⣿⣆⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⢂⠐⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⠎⡵⢣⢧⡹⣜⢣⣿⣿⣿⣿⣿⣿⣿⣷⡌⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⢂⠐⡀⢂⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠡⢚⠴⣉⠦⡑⢎⢣⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⣙⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⡩⠂⠀⠀⠀⠀⠀⣀⡔⢦⠃⢈⠐⡀⢂⠐⠠⠀⠄⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠁⠎⡰⢡⠙⡌⣸⣿⣿⣿⣿⣿⣿⣿⠿⠿⠟⠒⠌⠻⢿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠉⠀⠈⠀⠀⠀⠀⠀⣀⠶⡱⢎⢧⢋⠀⡐⢀⠂⠌⢀⠂⢀⠂⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠢⠑⡨⣟⠿⠟⠟⠋⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠛⠟⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢴⡩⢞⡱⢫⠜⡪⢅⠀⠂⠄⠂⠠⠀⠂⢀⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢢⡙⢦⡙⡔⢣⠈⢀⠂⠈⡀⠐⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠂⠴⢉⠆⡁⠀⡀⠁⢀⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠐⠡⠀⠀⠐⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                     OPERATION EYES ON
"""

# Global state
FOUND_CAMS = []
FILTER_MODE = "ALL"

# Country codes for targeted scans
COUNTRIES = {
    "US": "United States", "JP": "Japan", "IT": "Italy", "DE": "Germany",
    "RU": "Russia", "FR": "France", "KR": "Korea", "TW": "Taiwan",
    "NO": "Norway", "CA": "Canada", "GB": "United Kingdom", "NL": "Netherlands",
    "SE": "Sweden", "ES": "Spain", "CH": "Switzerland", "AT": "Austria",
    "PL": "Poland", "CZ": "Czech Republic", "RO": "Romania", "BR": "Brazil"
}

# ══════════════════════════════════════════════════════════════════════════════
# INSECAM SCRAPER
# ══════════════════════════════════════════════════════════════════════════════

class InsecamScraper:
    """Scrapes the Insecam public camera directory."""
    
    def build_url(self, country=None, page=1):
        if country:
            return f"{INSECAM_BASE}/bycountry/{country}/?page={page}"
        return f"{INSECAM_BASE}/byrating/?page={page}"
    
    def scrape_page(self, url):
        """Extract camera URLs from a single Insecam page."""
        cameras = []
        try:
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                for img in soup.find_all('img'):
                    src = img.get('src', '')
                    title = img.get('title', '')
                    
                    # Skip static assets
                    if 'http' in src and 'static' not in src and 'insecam' not in src:
                        brand, location = self._parse_title(title)
                        cameras.append({
                            'url': src,
                            'brand': brand,
                            'location': location
                        })
        except Exception:
            pass
        return cameras
    
    def _parse_title(self, title):
        """Extract brand and location from Insecam title."""
        brand, location = "IP Camera", "Unknown"
        try:
            if " in " in title:
                parts = title.split(" in ")
                location = parts[1].strip()
                if "Live camera " in parts[0]:
                    brand = parts[0].replace("Live camera ", "").strip() or "IP Camera"
        except:
            pass
        return brand, location
    
    def scrape(self, country=None, max_pages=5):
        """Scrape multiple pages in parallel."""
        all_cameras = []
        print(f"{Fore.CYAN}[*] Scraping Insecam ({max_pages} pages)...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            urls = [self.build_url(country, page) for page in range(1, max_pages + 1)]
            results = executor.map(self.scrape_page, urls)
            
            for cameras in results:
                all_cameras.extend(cameras)
        
        # Remove duplicates
        unique = {cam['url']: cam for cam in all_cameras}
        print(f"{Fore.GREEN}[+] Found {len(unique)} unique feeds from Insecam")
        return list(unique.values())

# ══════════════════════════════════════════════════════════════════════════════
# SEARCH ENGINE DORKING
# ══════════════════════════════════════════════════════════════════════════════

class DorkEngine:
    """Multi-engine Google dorking for camera discovery."""
    
    def search_yahoo(self, query, limit=50):
        """Search Yahoo with stealth headers."""
        results = []
        start = 1
        
        while len(results) < limit:
            time.sleep(random.uniform(1.0, 2.0))
            
            try:
                headers = {
                    'User-Agent': random.choice(USER_AGENTS),
                    'Accept': 'text/html,application/xhtml+xml',
                    'Referer': 'https://www.google.com/'
                }
                
                url = f"https://search.yahoo.com/search?p={query}&b={start}&pz=10"
                response = requests.get(url, headers=headers, timeout=15)
                
                if response.status_code != 200:
                    break
                
                soup = BeautifulSoup(response.text, 'html.parser')
                algo_divs = soup.find_all('div', class_='algo')
                
                if not algo_divs:
                    break
                
                for div in algo_divs:
                    link = div.find('a')
                    if link:
                        href = self._extract_yahoo_url(link.get('href', ''))
                        if href and 'yahoo.com' not in href:
                            results.append({'url': href, 'brand': 'IP Camera', 'location': 'Unknown'})
                            if len(results) >= limit:
                                break
                
                start += 10
            except:
                break
        
        return results
    
    def _extract_yahoo_url(self, raw_url):
        """Extract real URL from Yahoo redirect."""
        if '/RU=' in raw_url:
            try:
                start = raw_url.find('/RU=') + 4
                end = raw_url.find('/', start)
                if end == -1:
                    end = len(raw_url)
                return unquote(raw_url[start:end])
            except:
                pass
        return raw_url if 'http' in raw_url else None
    
    def search_startpage(self, query, limit=50):
        """Search Startpage (Google proxy)."""
        results = []
        seen = set()
        
        try:
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            response = requests.post(
                "https://www.startpage.com/sp/search",
                data={'query': query, 'cat': 'web', 'language': 'english'},
                headers=headers,
                timeout=15
            )
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if 'http' in href and 'startpage' not in href and href not in seen:
                        if 'reddit' not in href and 'mastodon' not in href:
                            seen.add(href)
                            results.append({'url': href, 'brand': 'IP Camera', 'location': 'Unknown'})
                            if len(results) >= limit:
                                break
        except:
            pass
        
        return results
    
    def process_dork(self, dork, limit=20):
        """Run a dork through multiple engines in parallel."""
        all_results = []
        seen = set()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            yahoo_future = executor.submit(self.search_yahoo, dork, limit)
            startpage_future = executor.submit(self.search_startpage, dork, limit)
            
            for future in concurrent.futures.as_completed([yahoo_future, startpage_future]):
                try:
                    for result in future.result():
                        if result['url'] not in seen:
                            seen.add(result['url'])
                            all_results.append(result)
                except:
                    pass
        
        return all_results
    
    def scan(self, limit=20):
        """Run all dorks and stream results."""
        print(f"{Fore.CYAN}[*] Running {len(CAMERA_DORKS)} camera dorks...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_map = {executor.submit(self.process_dork, dork, limit): dork for dork in CAMERA_DORKS}
            
            for future in concurrent.futures.as_completed(future_map):
                try:
                    for result in future.result():
                        yield result
                except:
                    pass

# ══════════════════════════════════════════════════════════════════════════════
# CAMERA VERIFIER WITH GEOIP
# ══════════════════════════════════════════════════════════════════════════════

class CameraVerifier:
    """Verify camera streams and enrich with GeoIP data."""
    
    def get_location(self, host):
        """Lookup geographic location for an IP/hostname."""
        try:
            response = requests.get(
                f"http://ip-api.com/json/{host}?fields=status,country,city",
                timeout=3
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    city = data.get('city', 'Unknown')
                    country = data.get('country', 'Unknown')
                    return f"{city}, {country}"
        except:
            pass
        return "Unknown"
    
    def verify(self, camera):
        """Check if camera is live and determine stream type."""
        url = camera['url']
        
        try:
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            response = requests.get(url, timeout=6, stream=True, headers=headers)
            
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '').lower()
                server = response.headers.get('Server', 'Unknown')
                
                # Determine camera type
                cam_type = None
                if 'multipart' in content_type or 'x-mixed-replace' in content_type:
                    cam_type = 'LIVE STREAM (MJPEG)'
                elif 'image' in content_type:
                    cam_type = 'SNAPSHOT (JPEG)'
                elif 'video' in content_type:
                    cam_type = 'VIDEO FEED'
                
                if cam_type:
                    # Apply filter
                    if FILTER_MODE == 'STREAM' and 'STREAM' not in cam_type:
                        return None
                    if FILTER_MODE == 'SNAPSHOT' and 'SNAPSHOT' not in cam_type:
                        return None
                    
                    # Get location if not already known
                    location = camera.get('location', 'Unknown')
                    if location == 'Unknown':
                        try:
                            host = urlparse(url).hostname
                            location = self.get_location(host)
                        except:
                            pass
                    
                    return {
                        'url': url,
                        'status': 'Live',
                        'type': cam_type,
                        'server': server,
                        'brand': camera.get('brand', 'IP Camera'),
                        'location': location
                    }
        except:
            pass
        
        return None

# ══════════════════════════════════════════════════════════════════════════════
# USER INTERFACE
# ══════════════════════════════════════════════════════════════════════════════

def center_text(text, width=120):
    """Center text for display."""
    # Remove color codes to calculate actual length
    clean = text
    for code in [Fore.RED, Fore.GREEN, Fore.CYAN, Fore.YELLOW, Fore.WHITE, Fore.BLUE, Fore.MAGENTA, Style.BRIGHT, Style.RESET_ALL]:
        clean = clean.replace(code, '')
    padding = max(0, (width - len(clean)) // 2)
    return ' ' * padding + text

def print_banner():
    """Display the application banner."""
    # Print each line of ASCII art centered
    for line in BANNER.strip().split('\n'):
        print(Fore.RED + center_text(line))
    
    print()
    print(center_text(f"{Style.BRIGHT}{Fore.WHITE}v3.0 | GLOBAL SURVEILLANCE | UNIFIED INTELLIGENCE"))
    print(center_text(f"{Style.BRIGHT}{Fore.YELLOW}Made by Y0oshi | IG: @rde0"))
    print(center_text(Fore.WHITE + '-' * 80))

def run_scan(country=None, pages=3, mode='DORK'):
    """Execute a scan operation."""
    global FOUND_CAMS
    
    insecam = InsecamScraper()
    dorker = DorkEngine()
    verifier = CameraVerifier()
    
    seen_urls = set()
    
    print(f"\n{Style.BRIGHT}{Fore.YELLOW}" + center_text(f"=== SCANNING ({mode}) ==="))
    print()
    
    def verify_and_print(camera):
        if camera['url'] in seen_urls:
            return
        seen_urls.add(camera['url'])
        
        result = verifier.verify(camera)
        if result:
            color = Fore.GREEN if 'STREAM' in result['type'] else Fore.CYAN
            print(f"{color}[+] {Fore.WHITE}{result['url']} {Fore.MAGENTA}({result['brand']} | {result['location']})")
            FOUND_CAMS.append(result)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        # Insecam scraping
        if mode in ['UNIFIED', 'INSECAM']:
            cameras = insecam.scrape(country=country, max_pages=pages)
            executor.map(verify_and_print, cameras)
        
        # Dorking
        if mode in ['UNIFIED', 'DORK']:
            for camera in dorker.scan(limit=pages * 10):
                executor.submit(verify_and_print, camera)
    
    print(f"\n{Fore.CYAN}[*] Scan complete. Found {len(FOUND_CAMS)} live cameras.")
    
    # Save results
    filename = f"scan_result_{int(time.time())}.json"
    with open(filename, 'w') as f:
        json.dump(FOUND_CAMS, f, indent=4)
    print(f"{Fore.BLUE}[*] Results saved to {filename}")

def resize_terminal(rows=40, cols=125):
    """Resize the terminal window to fit content."""
    sys.stdout.write(f"\x1b[8;{rows};{cols}t")

def main():
    """Main application entry point."""
    global FILTER_MODE
    
    resize_terminal()
    print_banner()
    
    print(f"\n{Fore.WHITE}Commands:")
    print(f"  {Fore.CYAN}/scrape [pages]{Fore.WHITE}  - Scrape Insecam directory")
    print(f"  {Fore.CYAN}/scan [pages]{Fore.WHITE}    - Deep search with dorks")
    print(f"  {Fore.CYAN}/country [code]{Fore.WHITE}  - Set target country")
    print(f"  {Fore.CYAN}/mode [type]{Fore.WHITE}     - Filter: ALL, STREAM, SNAPSHOT")
    print(f"  {Fore.CYAN}/exit{Fore.WHITE}            - Quit")
    
    target_country = None
    
    while True:
        try:
            cmd = input(f"\n{Fore.RED}eyes-on ({FILTER_MODE})> {Fore.WHITE}").strip()
            if not cmd:
                continue
            
            parts = cmd.split()
            command = parts[0].lower()
            
            if command == '/scrape':
                pages = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 3
                run_scan(country=target_country, pages=pages, mode='INSECAM')
            
            elif command == '/scan':
                pages = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 3
                run_scan(country=target_country, pages=pages, mode='DORK')
            
            elif command == '/country':
                if len(parts) > 1:
                    code = parts[1].upper()
                    if code in COUNTRIES:
                        target_country = code
                        print(f"{Fore.GREEN}[+] Target: {code} ({COUNTRIES[code]})")
                    else:
                        print(f"{Fore.RED}[-] Invalid country code")
            
            elif command == '/mode':
                if len(parts) > 1:
                    mode = parts[1].upper()
                    if mode in ['ALL', 'STREAM', 'SNAPSHOT']:
                        FILTER_MODE = mode
                        print(f"{Fore.GREEN}[+] Filter set to {FILTER_MODE}")
                    else:
                        print(f"{Fore.RED}[-] Invalid mode")
                else:
                    print(f"{Fore.YELLOW}[*] Current: {FILTER_MODE}")
            
            elif command == '/exit':
                sys.exit(0)
            
            elif command == '/clear':
                print('\033[H\033[J', end='')
                print_banner()
        
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}Aborted.")
            break
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {e}")

if __name__ == '__main__':
    main()
