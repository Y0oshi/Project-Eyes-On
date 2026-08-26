#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  OPERATION EYES ON v4.0                                                       ║
║  Public IP Camera Reconnaissance Tool                                        ║
║  Coded by: Y0oshi | IG: @rde0                                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

A reconnaissance tool for discovering publicly accessible IP cameras using:
  - Insecam directory crawling (types -> camera pages -> live stream URLs)
  - Multi-engine dorking (Yahoo + Bing)
  - Deep harvesting of embedded camera URLs from listing/directory pages
  - Live stream verification with GeoIP enrichment

For educational and authorized security research purposes only. Only targets
devices that are already publicly exposed without authentication.
"""

import argparse
import base64
import concurrent.futures
import csv
import ipaddress
import json
import os
import random
import re
import select
import sys
import threading
import time

try:
    import termios
    import tty
    HAS_TERMIOS = True
except ImportError:  # non-Unix (e.g. Windows) — TUI falls back to CLI
    HAS_TERMIOS = False
from html import unescape as html_unescape
from urllib.parse import urljoin, urlparse, unquote, quote, urlunparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
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

CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".config", "eyeson", "config.json")

# Domains/substrings that are documentation, listings of docs, or helper sites.
# Dork results from these are almost never a live camera and are filtered out.
JUNK_DOMAINS = [
    "home-assistant", "hass.", "ispy", "ispyconnect", "virustotal", "github",
    "gitlab", "stackoverflow", "stackexchange", "superuser", "reddit", "wikipedia",
    "wikihow", "amazon", "ebay", "youtube", "youtu.be", "docs.", "support.",
    "microsoft", "msn.", "bing.com", "yahoo.com", "google.", "mastodon",
    "twitter", "x.com", "facebook", "instagram", "tiktok", "linkedin",
    "pinterest", "quora", "medium", "schneier", "shodan", "censys", "exploit",
    "nmap", "metasploit", "tutorial", "forum", "howto", "wordpress", "blogger",
    "cvedetails", "cve", "exploit-db", "packetstorm", "thehackernews",
]

# Text signatures of a search engine bot-check / rate-limit page
BLOCK_MARKERS = [
    "captcha", "unusual traffic", "verify you are human", "are you a robot",
    "automated requests", "too many requests", "rate limit", "security check",
    "not a robot", "enable javascript and cookies", "challenge",
]

# Camera discovery dorks - organized by manufacturer
CAMERA_DORKS = [
    # Axis Communications
    'inurl:"/view/index.shtml"',
    'inurl:"/view/view.shtml"',
    'intitle:"Live View / - AXIS"',
    'inurl:axis-cgi/jpg',
    'inurl:axis-cgi/mjpg',
    'intitle:"AXIS 240 Camera Server"',
    'intitle:"Live View / - AXIS 206M"',
    'intitle:"Live View / - AXIS 210"',
    'intitle:"Live View / - AXIS 211"',
    'intitle:"Live View / - AXIS 213 PTZ"',
    'intitle:"Live View / - AXIS 206W"',
    'intitle:"Live View / - AXIS 210W"',
    'inurl:indexFrame.shtml Axis',
    'intitle:"Axis 2400 Video Server"',
    'inurl:/view/indexFrame.shtml',
    'intitle:"live view" intitle:axis',
    'intitle:axis intitle:"video server"',
    'intitle:"Live View / - AXIS 706W"',

    # Hikvision
    'intitle:"Hikvision Web Cameras"',
    'inurl:"/doc/page/login.asp" intext:"Hikvision"',
    'intitle:"Hikvision" inurl:"login.asp"',
    'inurl:"/onvif-http/snapshot?auth="',
    'product:"Hikvision IP Camera"',

    # Mobotix
    'inurl:"/cgi-bin/guestimage.html"',
    'inurl:"/control/faststream.jpg"',
    'intitle:"MOBOTIX" inurl:"/control/userimage.html"',
    '(intitle:MOBOTIX intitle:PDAS) | (intitle:MOBOTIX intitle:Seiten)',
    'inurl:/pda/index.html +camera',

    # Foscam
    'intitle:"Foscam" inurl:"login.htm"',
    'inurl:"/videostream.cgi?user="',
    'intitle:"Foscam" inurl:"/live.htm"',

    # Panasonic
    'inurl:"/CgiStart?page=Single"',
    'intitle:"Panasonic Network Camera"',
    'inurl:"/nphMotionJpeg?Resolution="',
    'inurl:/config/cam_portal.cgi "Panasonic"',
    'inurl:"/ViewerFrame?Mode="',
    'inurl:"/ViewerFrame?Mode=Motion"',
    'intitle:"Panasonic" inurl:"ViewerFrame?Mode="',
    'inurl:"MultiCameraFrame?Mode=Motion"',
    'inurl:"WJ-NTI 04 Main Page"',
    'inurl:/live.htm intext:"M-JPEG"|"System Log"|"Camera-1"|"View Control"',

    # D-Link
    'intitle:"D-Link" inurl:"/video.htm"',
    'inurl:"/mjpg/video.cgi" intitle:"D-Link"',
    'intitle:"D-Link DCS-"',
    'inurl:"/eng/admin/adv_audiovideo.cgi"',

    # Sony
    'intitle:"sony network camera snc-pl"',
    'intitle:"Sony" inurl:"/home/homeJ.html"',
    'intitle:"SNC-RZ30" -demo',
    'intitle:"sony network camera snc-ml"',
    'inurl:"/image/webcam.jpg" intitle:"Sony"',
    'intitle:snc-220 inurl:home/',
    'intitle:snc-cs3 inurl:home/',
    'intitle:snc-r230 inurl:home/',

    # Canon
    'intitle:"Network Camera VB-M600"',
    'inurl:"/sample/LvAppl/lvappl.htm"',
    'inurl:"lvappl.htm"',
    'inurl:"/view.shtml" "camera"',

    # Vivotek
    'server:VVTK-HTTP-Server',
    'inurl:"/cgi-bin/viewer/video.jpg"',
    'intitle:"Vivotek Camera" inurl:/viewer',
    'intitle:"Vivotek" intext:"live view"',
    'intitle:"Vivotek" inurl:/cgi-bin/',
    'inurl:/vivotek/ rtsp',

    # WebcamXP / Webcam 7
    'intitle:"webcamXP 5"',
    'intitle:"webcam 7"',
    'intext:"powered by webcamXP 5"',
    'inurl:"/cam_1.jpg" intitle:"webcamXP"',
    'intitle:"webcam 7" inurl:"/gallery.html"',
    'intitle:"webcamXP 5" -download',
    'intitle:"webcam 7" inurl:"8080" -intext:"8080"',
    'intitle:"webcamXP 5" inurl:8080 \'Live\'',
    'intitle:"WEBCAM 7 " -inurl:/admin.html',

    # Dahua
    'intitle:"Dahua IP Camera" inurl:/login',
    'inurl:dahua inurl:view/view.shtml',
    'intitle:"Dahua" inurl:"/cgi-bin/rpc.cgi?action=login"',
    'intext:"Dahua" intitle:"Network Camera" inurl:main.cgi',

    # Reolink
    'intitle:"Reolink" inurl:view',
    'intitle:"Reolink Camera" inurl:login',
    'intitle:"Reolink" inurl:snapshot.cgi',
    'intitle:"Reolink" inurl:/cgi-bin/',
    'inurl:"/Reolink" intitle:"Live" -shop -store',

    # Ubiquiti / UniFi
    'intitle:"UniFi Video" inurl:login',
    'intitle:"UniFi Protect" inurl:7443',
    'inurl:snap.jpg intext:"ubiquiti"',
    'intitle:"UniFi Protect" inurl:/protect/live',
    'inurl:/cc/view.html intext:"unifi"',

    # Blue Iris
    'intitle:"Blue Iris Login"',
    'intitle:"Blue Iris Remote View"',

    # Android IP Webcam
    'inurl:"videomgr.html"',
    'intitle:"Android IP Webcam"',

    # Generic CGI / Directory
    'inurl:"/cgi-bin/live.cgi"',
    'inurl:"/cgi-bin/stream.cgi"',
    'inurl:"/cgi-bin/snapshot.cgi"',
    'inurl:"/cgi-bin/camctrl.cgi"',
    'intitle:"Index of /DCIM"',
    'inurl:"logo.bmp" intitle:"Webcam"',

    # Broad / Catch-all
    'intitle:"Live View" inurl:"login.cgi"',
    'intitle:"IP Camera" inurl:"login.html"',
    'inurl:"/view/index.shtml" -inurl:axis',
    'inurl:"/view/view.shtml" -inurl:axis',
    'inurl:"/main.cgi?next_file=main_fs.htm"',

    # GeoVision
    'intitle:"GeoVision WebCam Server" inurl:/WebCam',
    'intitle:"GeoVision" inurl:/login.htm',
    'inurl:/geovision/ login',
    'intitle:"GeoVision MultiCam Surveillance System" live view',

    # Avigilon
    'intitle:"Avigilon Control Center" inurl:/login',
    'inurl:/avigilon/viewer',
    'intitle:"Avigilon" intext:"live video"',
    'inurl:/avigilon/webclient/',

    # ZoneMinder
    'intitle:"ZoneMinder" inurl:/zm/index.php',
    'intext:"ZoneMinder" inurl:view=event',
    'inurl:/zoneminder/cgi-bin/nph-zms',

    # Legacy Webcam 7 / XP Ports
    'intitle:"webcam 7" inurl::8080',
    'intitle:"webcam 7" inurl::8081',
    'intitle:"webcam 7" inurl::8000',
    'intitle:"webcamXP 5" inurl::8080',

    # Shodan-Adapted / Misc
    'product:"Hikvision IP Camera"',
    'title:"IPCam Client"',
    'http.title:"WEB VIEW" dahua',

    # Toshiba
    'intitle:"Toshiba Network Camera"',
    'inurl:"/user/index.html" intitle:"Toshiba"',
    'intitle:"Toshiba Network Camera" user Login',

    # Generic / Other
    'inurl:"/mjpg/video.mjpg"',
    'inurl:"/axis-cgi/mjpg"',
    'inurl:"view/index.shtml"',
    'inurl:"/view/view.shtml"',
    'inurl:"/c/version.cgi"',
    'inurl:"/cgi-bin/mjpg/video.cgi"',
    'inurl:"/cgi-bin/video.jpg"',
    'inurl:"/live/index.html"',
    'inurl:"/live/view.html"',
    'inurl:"/mjpg/video.cgi?camera"',
    'inurl:"/mjpg/video.cgi?channel"',
    'inurl:"/nph-mjpeg.cgi"',
    'inurl:"/out.jpg"',
    'inurl:"/snapshot.cgi?"',
    'inurl:"/stream/video.mjpeg"',
    'inurl:"/video.cgi"',
    'inurl:"/video.mjpg"',
    'inurl:"/view/index.shtml" intitle:"Network Camera"',
    'inurl:"CgiStart?page="',
    'inurl:camctrl.cgi',
    'intitle:"IP CAMERA Viewer"',
    'intitle:"NetCam Live Image"',
    'intitle:"WJ-HD150" inurl:"/login.html"',
    'intitle:"WJ-ND200" inurl:"/login.html"',
    'intitle:"i-Catcher Console - Web Monitor"',
    'intitle:"netcam live image" (disconnected)',
    'inurl:"/gallery.html" intitle:"IP Camera"',
    'inurl:":8081" intitle:"IP Camera"',
    'inurl:":8080" intitle:"IP Camera"',
    'inurl:"/guestimage.html"',
    'inurl:"/live.htm" intext:"M-JPEG"',
    'inurl:"/monitor/bflowmo.jpg"',
    'inurl:"/multiview.htm"',
    'inurl:"/view.shtml" "Network Camera"',
    'inurl:"/viewer/live.shtml"',
    'inurl:"/webapp/live/show.html"',
    'inurl:"/webcam.html"',
    'inurl:"camera-cgi/admin/param.cgi"',
    'inurl:"cgi-bin/guestimage.html"',
    'inurl:"guestimage.html" intitle:"IP Camera"',
    'inurl:"image.jpg" intitle:"IP Camera"',
    'inurl:"index.html" intitle:"Live View / - AXIS"',
    'inurl:"live/cam.html"',
    'inurl:"live/mjpeg"',
    'inurl:"mjpg/video.mjpg" intitle:"IP Camera"',
    'inurl:"nphMotionJpeg?Resolution="',
    'inurl:"snapshot.jpg"',
    'inurl:"video.mjpg"',
    'inurl:"view/index.shtml" intitle:"Axis"',
    'inurl:"view/view.shtml" intitle:"Axis"',
    'inurl:User/General_home.htm',
    'inurl:ViewerFrame?M0de=',
    'inurl:axis-cgi/mjpg (motion-JPEG)',
    'inurl:indexFrame.shtml',
    'inurl:live/cam.html',
    'inurl:top.htm inurl:currenttime',
    'inurl:view/indexFrame.shtml',
    'inurl:view/viewer_index.shtml',
    'intitle:"IP CAMERA Viewer" intext:"setting |Client setting"',
    'intitle:"yawcam" inurl:":8081"',
    'intitle:"iGuard Fingerprint Security System"',
    'intitle:"Edr1680 remote viewer"',
    'intitle:"NetCam Live Image" -.edu -.gov',
    'intitle:"INTELLINET" intitle:"IP Camera Homepage"',
    'intitle:"WEBDVR" -inurl:product -inurl:demo',
    'intitle:"Middle frame of Videoconference Management System" ext:htm',
    'intitle:"--- VIDEO WEB SERVER ---" intext:"Video Web Server" "Any time & Any where" username password',
    'intitle:HomeSeer.Web.Control | Home.Status.Events.Log',
    'intitle:"supervisioncam protocol"',
    'intitle:"active webcam page"',
    'VB Viewer inurl:/viewer/live/ja/live.html',
    'inurl:control/camerainfo',
    'inurl:"/view/view.shtml?id="',
    'allintitle:Edr1680 remote viewer',
    'allintitle:EverFocus |EDSR |EDSR400 Applet',
    'allintitle:EDR1600 login |Welcome',
    'intitle:"BlueNet Video Viewer"',
    '(intitle:(EyeSpyFX|OptiCamFX) "go to camera")|(inurl:servlet/DetectBrowser)',
    'intitle:"Veo Observer XT"',
    'inurl:shtml|pl|php|htm|asp|aspx|pDf|cfm -(intext:observer)',
    'inurl:"/view.shtml"',
    'inurl:"ViewerFrame?M0de=Refresh"',
    'liveapplet',
    'intitle:liveapplet',
    'allintitle:"Network Camera NetworkCamera" (disconnected)',
    'intitle:liveapplet inurl:LvAppl',
    'intitle:"EvoCam" inurl:"webcam.html"',
    'intitle:"Live NetSnap Cam-Server feed"',
    'intitle:start inurl:cgistart',
    'site:.viewnetcam.com -www.viewnetcam.com',
    'intitle:"IP Webcam" inurl:"/greet.html"',
    'intitle:"NetCamSC*"',
    'intitle:"NetCamXL*"',
    'intitle:"NetCamSC*" | intitle:"NetCamXL*" inurl:index.html',
    '"Camera Live Image" inurl:"guestimage.html"',
    'intitle:"webcam" inurl:login',
    'inurl:/ViewerFrame? intitle:"Network Camera NetworkCamera"',
    'intitle:NetworkCamera intext:"Pan / Tilt" inurl:ViewerFrame',
    'intitle:"IP CAMERA Viewer" intext:"setting | Client setting"',
    'intitle:"Weather Wing WS-2"',

    # Linksys
    'intitle:"Linksys Viewer - Login" -inurl:mainFrame',
    'inurl:"main.cgi?next_file=main_fs.htm"',

    # TP-Link
    'intitle:"TP-LINK IP-Camera"',

    # Other / Generic Additions
    'intitle:"netcam watcher"',
    'intitle:"Network Camera NetworkCamera"',
    'intitle:"Webcam" inurl:WebCam.htm',
    'intitle:webcamxp inurl:8080',
    'inurl:"snapshot.cgi?user="',
]

# De-duplicate while preserving order
CAMERA_DORKS = list(dict.fromkeys(CAMERA_DORKS))

# Fallback list of Insecam camera types, used if dynamic discovery fails.
INSECAM_TYPES = [
    "Android-IPWebcam", "Axis", "Axis2", "AxisMkII", "BlueIris", "Bosch",
    "Canon", "ChannelVision", "Defeway", "DLink", "DLink-DCS-932", "Foscam",
    "FoscamIPCam", "Fullhan", "GK7205", "Hi3516", "Linksys", "Megapixel",
    "Mobotix", "Motion", "Panasonic", "PanasonicHD", "Sony", "Sony-CS3",
    "StarDot", "Streamer", "SunellSecurity", "Toshiba", "TPLink", "Vije",
    "Vivotek", "WebcamXP", "WIFICam", "WYM", "Yawcam"
]

# Full ISO 3166-1 alpha-2 country codes -> names
COUNTRIES = {
    "AD": "Andorra", "AE": "United Arab Emirates", "AF": "Afghanistan",
    "AG": "Antigua and Barbuda", "AI": "Anguilla", "AL": "Albania",
    "AM": "Armenia", "AO": "Angola", "AQ": "Antarctica", "AR": "Argentina",
    "AS": "American Samoa", "AT": "Austria", "AU": "Australia", "AW": "Aruba",
    "AX": "Aland Islands", "AZ": "Azerbaijan", "BA": "Bosnia and Herzegovina",
    "BB": "Barbados", "BD": "Bangladesh", "BE": "Belgium", "BF": "Burkina Faso",
    "BG": "Bulgaria", "BH": "Bahrain", "BI": "Burundi", "BJ": "Benin",
    "BL": "Saint Barthelemy", "BM": "Bermuda", "BN": "Brunei", "BO": "Bolivia",
    "BQ": "Bonaire", "BR": "Brazil", "BS": "Bahamas", "BT": "Bhutan",
    "BV": "Bouvet Island", "BW": "Botswana", "BY": "Belarus", "BZ": "Belize",
    "CA": "Canada", "CC": "Cocos Islands", "CD": "Democratic Republic of the Congo",
    "CF": "Central African Republic", "CG": "Congo", "CH": "Switzerland",
    "CI": "Ivory Coast", "CK": "Cook Islands", "CL": "Chile", "CM": "Cameroon",
    "CN": "China", "CO": "Colombia", "CR": "Costa Rica", "CU": "Cuba",
    "CV": "Cape Verde", "CW": "Curacao", "CX": "Christmas Island", "CY": "Cyprus",
    "CZ": "Czech Republic", "DE": "Germany", "DJ": "Djibouti", "DK": "Denmark",
    "DM": "Dominica", "DO": "Dominican Republic", "DZ": "Algeria", "EC": "Ecuador",
    "EE": "Estonia", "EG": "Egypt", "EH": "Western Sahara", "ER": "Eritrea",
    "ES": "Spain", "ET": "Ethiopia", "FI": "Finland", "FJ": "Fiji",
    "FK": "Falkland Islands", "FM": "Micronesia", "FO": "Faroe Islands",
    "FR": "France", "GA": "Gabon", "GB": "United Kingdom", "GD": "Grenada",
    "GE": "Georgia", "GF": "French Guiana", "GG": "Guernsey", "GH": "Ghana",
    "GI": "Gibraltar", "GL": "Greenland", "GM": "Gambia", "GN": "Guinea",
    "GP": "Guadeloupe", "GQ": "Equatorial Guinea", "GR": "Greece",
    "GS": "South Georgia", "GT": "Guatemala", "GU": "Guam", "GW": "Guinea-Bissau",
    "GY": "Guyana", "HK": "Hong Kong", "HM": "Heard Island", "HN": "Honduras",
    "HR": "Croatia", "HT": "Haiti", "HU": "Hungary", "ID": "Indonesia",
    "IE": "Ireland", "IL": "Israel", "IM": "Isle of Man", "IN": "India",
    "IO": "British Indian Ocean Territory", "IQ": "Iraq", "IR": "Iran",
    "IS": "Iceland", "IT": "Italy", "JE": "Jersey", "JM": "Jamaica",
    "JO": "Jordan", "JP": "Japan", "KE": "Kenya", "KG": "Kyrgyzstan",
    "KH": "Cambodia", "KI": "Kiribati", "KM": "Comoros", "KN": "Saint Kitts and Nevis",
    "KP": "North Korea", "KR": "South Korea", "KW": "Kuwait", "KY": "Cayman Islands",
    "KZ": "Kazakhstan", "LA": "Laos", "LB": "Lebanon", "LC": "Saint Lucia",
    "LI": "Liechtenstein", "LK": "Sri Lanka", "LR": "Liberia", "LS": "Lesotho",
    "LT": "Lithuania", "LU": "Luxembourg", "LV": "Latvia", "LY": "Libya",
    "MA": "Morocco", "MC": "Monaco", "MD": "Moldova", "ME": "Montenegro",
    "MF": "Saint Martin", "MG": "Madagascar", "MH": "Marshall Islands",
    "MK": "North Macedonia", "ML": "Mali", "MM": "Myanmar", "MN": "Mongolia",
    "MO": "Macao", "MP": "Northern Mariana Islands", "MQ": "Martinique",
    "MR": "Mauritania", "MS": "Montserrat", "MT": "Malta", "MU": "Mauritius",
    "MV": "Maldives", "MW": "Malawi", "MX": "Mexico", "MY": "Malaysia",
    "MZ": "Mozambique", "NA": "Namibia", "NC": "New Caledonia", "NE": "Niger",
    "NF": "Norfolk Island", "NG": "Nigeria", "NI": "Nicaragua", "NL": "Netherlands",
    "NO": "Norway", "NP": "Nepal", "NR": "Nauru", "NU": "Niue", "NZ": "New Zealand",
    "OM": "Oman", "PA": "Panama", "PE": "Peru", "PF": "French Polynesia",
    "PG": "Papua New Guinea", "PH": "Philippines", "PK": "Pakistan",
    "PL": "Poland", "PM": "Saint Pierre and Miquelon", "PN": "Pitcairn",
    "PR": "Puerto Rico", "PS": "Palestine", "PT": "Portugal", "PW": "Palau",
    "PY": "Paraguay", "QA": "Qatar", "RE": "Reunion", "RO": "Romania",
    "RS": "Serbia", "RU": "Russia", "RW": "Rwanda", "SA": "Saudi Arabia",
    "SB": "Solomon Islands", "SC": "Seychelles", "SD": "Sudan", "SE": "Sweden",
    "SG": "Singapore", "SH": "Saint Helena", "SI": "Slovenia", "SJ": "Svalbard",
    "SK": "Slovakia", "SL": "Sierra Leone", "SM": "San Marino", "SN": "Senegal",
    "SO": "Somalia", "SR": "Suriname", "SS": "South Sudan",
    "ST": "Sao Tome and Principe", "SV": "El Salvador", "SX": "Sint Maarten",
    "SY": "Syria", "SZ": "Eswatini", "TC": "Turks and Caicos Islands",
    "TD": "Chad", "TF": "French Southern Territories", "TG": "Togo",
    "TH": "Thailand", "TJ": "Tajikistan", "TK": "Tokelau", "TL": "Timor-Leste",
    "TM": "Turkmenistan", "TN": "Tunisia", "TO": "Tonga", "TR": "Turkey",
    "TT": "Trinidad and Tobago", "TV": "Tuvalu", "TW": "Taiwan", "TZ": "Tanzania",
    "UA": "Ukraine", "UG": "Uganda", "UM": "United States Minor Outlying Islands",
    "US": "United States", "UY": "Uruguay", "UZ": "Uzbekistan", "VA": "Vatican",
    "VC": "Saint Vincent and the Grenadines", "VE": "Venezuela",
    "VG": "British Virgin Islands", "VI": "U.S. Virgin Islands", "VN": "Vietnam",
    "VU": "Vanuatu", "WF": "Wallis and Futuna", "WS": "Samoa", "YE": "Yemen",
    "YT": "Mayotte", "ZA": "South Africa", "ZM": "Zambia", "ZW": "Zimbabwe",
}

# Global state
FILTER_MODE = "ALL"

# ── HTTP session management (thread-local for connection reuse) ──────────────
_local = threading.local()


def get_session():
    """Return a thread-local requests.Session with retry/backoff configured."""
    if not hasattr(_local, "session"):
        s = requests.Session()
        retry = Retry(
            total=2,
            backoff_factor=0.6,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"],
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=20)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        _local.session = s
    return _local.session


def fetch(url, *, timeout=15, method="GET", data=None, cookies=None):
    """Perform a GET/POST request and return the Response, or None on failure."""
    s = get_session()
    headers = {"User-Agent": random.choice(USER_AGENTS), "Accept-Language": "en-US,en;q=0.9"}
    try:
        resp = s.request(method, url, headers=headers, timeout=timeout, data=data, cookies=cookies)
        if resp.status_code == 200:
            return resp
    except Exception:
        pass
    return None


def load_config():
    """Load default settings from the config file, if it exists."""
    defaults = {}
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "r") as f:
                data = json.load(f)
            if isinstance(data, dict):
                defaults = data
    except Exception:
        pass
    return defaults


def save_config(data):
    """Persist settings to the config file (best-effort)."""
    try:
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump(data, f, indent=4)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# INSECAM SCRAPER (3-stage crawl: types -> camera pages -> stream URLs)
# ══════════════════════════════════════════════════════════════════════════════

class InsecamScraper:
    """Crawls the Insecam public camera directory for live stream URLs."""

    def _discover_types(self):
        """Return a list of /en/bytype/<Type>/ URLs."""
        html = fetch(f"{INSECAM_BASE}/", timeout=15)
        if not html:
            return [f"{INSECAM_BASE}/bytype/{t}/" for t in INSECAM_TYPES]

        soup = BeautifulSoup(html.text, "html.parser")
        types = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if "/en/bytype/" in href:
                url = urljoin(INSECAM_BASE + "/", href)
                if url not in types:
                    types.append(url)
        if not types:
            types = [f"{INSECAM_BASE}/bytype/{t}/" for t in INSECAM_TYPES]
        return types

    @staticmethod
    def _parse_title(title):
        """Parse 'Live camera in Switzerland, Arosa' -> (country, city)."""
        country, city = "Unknown", "Unknown"
        m = re.search(r"Live camera in\s+(.+)", title, re.I)
        if m:
            loc = m.group(1).strip()
            if "," in loc:
                country, city = (p.strip() for p in loc.split(",", 1))
            else:
                country = loc
        return country, city

    def _collect_views(self, type_url, pages):
        """Collect camera-page IDs (plus location/brand) from a type listing."""
        type_name = type_url.rstrip("/").split("/")[-1]
        views = []
        for page in range(1, pages + 1):
            url = f"{type_url}?page={page}"
            html = fetch(url, timeout=8)
            if not html:
                continue
            soup = BeautifulSoup(html.text, "html.parser")
            anchors = soup.find_all("a", class_="thumbnail-item__wrap")
            if not anchors:
                break
            for a in anchors:
                href = a.get("href", "")
                if "/en/view/" not in href:
                    continue
                cid = href.rstrip("/").split("/")[-1]
                country, city = self._parse_title(a.get("title", ""))
                views.append({"id": cid, "country": country, "city": city, "brand": type_name})
        return views

    def _fetch_streams(self, view):
        """Fetch a camera view page and extract every live stream URL on it."""
        url = f"{INSECAM_BASE}/view/{view['id']}/"
        html = fetch(url, timeout=8)
        if not html:
            return []

        soup = BeautifulSoup(html.text, "html.parser")
        cams = []
        for img in soup.find_all("img", src=True):
            src = img["src"]
            if not src.startswith("http"):
                continue
            low = src.lower()
            if any(j in low for j in ("yandex", "insecam.org", "google", "logo", ".mc.")):
                continue

            stream = html_unescape(src)
            # Replace Insecam's COUNTER cache-buster token with a random number
            stream = re.sub(r"\bCOUNTER\b", str(random.randint(100000, 999999)), stream)

            city = view.get("city", "Unknown")
            country = view.get("country", "Unknown")
            alt = img.get("alt", "")
            m = re.search(r"Live camera in\s+(.+)", alt, re.I)
            if m:
                city = m.group(1).strip()
                # Related cameras on the same page may live in another country,
                # but their alt only carries a city — drop the inherited country.
                if city.lower() != view.get("city", "").lower():
                    country = "Unknown"

            cams.append({
                "url": stream,
                "brand": view.get("brand", "IP Camera"),
                "location": f"{city}, {country}",
            })
        return cams

    def scrape(self, country=None, max_pages=3, max_types=None):
        """Crawl Insecam and return unique live camera stream URLs."""
        types = self._discover_types()
        if max_types:
            types = types[:max_types]
        print(f"{Fore.CYAN}[*] Insecam: {len(types)} camera types, {max_pages} page(s) each")

        # Stage 1+2: collect camera pages (parallel across types)
        views = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            futs = [ex.submit(self._collect_views, t, max_pages) for t in types]
            for f in concurrent.futures.as_completed(futs):
                try:
                    views.extend(f.result())
                except Exception:
                    pass

        # Country filter happens before resolving streams (saves requests)
        if country:
            cname = COUNTRIES.get(country.upper(), country).lower()
            views = [v for v in views if cname in v["country"].lower() or v["country"].lower() in cname]

        print(f"{Fore.CYAN}[*] Insecam: resolving {len(views)} camera page(s)...")

        # Stage 3: resolve each view page to one or more stream URLs
        cameras = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            futs = [ex.submit(self._fetch_streams, v) for v in views]
            for f in concurrent.futures.as_completed(futs):
                try:
                    cameras.extend(f.result())
                except Exception:
                    pass

        unique = {c["url"]: c for c in cameras}
        print(f"{Fore.GREEN}[+] Insecam: {len(unique)} unique feed(s)")
        return list(unique.values())


# ══════════════════════════════════════════════════════════════════════════════
# SEARCH ENGINE DORKING
# ══════════════════════════════════════════════════════════════════════════════

# Search-engine registry: name -> DorkEngine search method
ENGINES = {
    "yahoo": "search_yahoo",
    "bing": "search_bing",
    "mojeek": "search_mojeek",
    "duckduckgo": "search_duckduckgo",
}

ENGINE_LABELS = {
    "yahoo": "Yahoo",
    "bing": "Bing",
    "mojeek": "Mojeek",
    "duckduckgo": "DuckDuckGo",
}


class DorkEngine:
    """Multi-engine dorking for camera discovery."""

    def __init__(self, engines=None):
        self._blocked = set()
        self._blocked_at = {}
        self._cooldown = 45  # seconds before retrying a blocked engine
        self._engines = engines or list(ENGINES)
        self._elocks = {}
        self._last = {}
        self._min_gap = 0.5  # base seconds between requests to the same engine

    def _engine_fetch(self, name, url, **kw):
        # One in-flight request per engine, spaced out so we don't get blocked.
        lock = self._elocks.setdefault(name, threading.Lock())
        with lock:
            now = time.time()
            gap = self._min_gap + random.uniform(0.0, 0.5) - (now - self._last.get(name, 0.0))
            if gap > 0:
                time.sleep(gap)
            self._last[name] = time.time()
            return fetch(url, **kw)

    def _engine_ok(self, name):
        """Return True if the engine should be queried (recovers after cooldown)."""
        if name not in self._blocked:
            return True
        if time.time() - self._blocked_at.get(name, 0) > self._cooldown:
            self._blocked.discard(name)
            return True
        return False

    @staticmethod
    def _looks_blocked(text):
        low = text.lower()
        return any(m in low for m in BLOCK_MARKERS)

    @staticmethod
    def _is_junk(url):
        host = urlparse(url).netloc.lower()
        return any(j in host for j in JUNK_DOMAINS)

    @staticmethod
    def _is_camera(url):
        # A camera is a public-IP host, or any host with a stream/snapshot path.
        host = urlparse(url).hostname or ""
        path = urlparse(url).path or ""
        try:
            ip = ipaddress.ip_address(host)
            # host is a literal IP: public -> keep (web UI or stream), private -> drop
            return not (ip.is_private or ip.is_loopback or ip.is_link_local
                        or ip.is_reserved or ip.is_multicast or ip.is_unspecified)
        except ValueError:
            pass
        # host is a domain: keep only if the URL carries a stream/snapshot path
        return bool(STREAM_PATH_RE.search(path))

    @staticmethod
    def _yahoo_redirect(href):
        """Decode a Yahoo /RU= redirect link back to the real URL."""
        if "/RU=" in href:
            try:
                ru = href.split("/RU=")[1].split("/RK=")[0]
                return unquote(ru)
            except Exception:
                return None
        if href.startswith("http") and "yahoo.com" not in href:
            return href
        return None

    @staticmethod
    def _bing_redirect(href):
        """Decode a Bing /ck/a redirect link back to the real URL."""
        if "/ck/a" in href:
            m = re.search(r"[?&]u=([^&]+)", href)
            if m:
                raw = m.group(1)
                # Bing prefixes the base64url payload with a type marker (e.g. "a1")
                if len(raw) > 2 and raw[:2] in ("a1", "a2"):
                    raw = raw[2:]
                try:
                    decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
                    return decoded.decode("utf-8", "ignore")
                except Exception:
                    return None
        if href.startswith("http") and "bing.com" not in href and "microsoft" not in href:
            return href
        return None

    def search_yahoo(self, query, limit=30):
        if not self._engine_ok("yahoo"):
            return []
        results = []
        b = 1
        while len(results) < limit:
            url = f"https://search.yahoo.com/search?p={quote(query)}&b={b}&pz=10"
            html = self._engine_fetch("yahoo", url, timeout=8)
            if not html:
                break
            soup = BeautifulSoup(html.text, "html.parser")
            anchors = soup.select('a[data-matarget="algo"]')
            if not anchors:
                anchors = [a for a in soup.select("div.algo a[href]")]
            if not anchors:
                if self._looks_blocked(html.text):
                    self._blocked.add("yahoo")
                    self._blocked_at["yahoo"] = time.time()
                    print(f"{Fore.YELLOW}[!] Yahoo rate-limited/blocked — pausing Yahoo queries.")
                break
            got = 0
            for a in anchors:
                u = self._yahoo_redirect(a.get("href", ""))
                if not u or self._is_junk(u):
                    continue
                results.append(u)
                got += 1
                if len(results) >= limit:
                    break
            if got == 0:
                break
            b += 10
        return results

    def search_bing(self, query, limit=30):
        if not self._engine_ok("bing"):
            return []
        results = []
        first = 1
        while len(results) < limit:
            url = f"https://www.bing.com/search?q={quote(query)}&count=10&first={first}"
            html = self._engine_fetch("bing", url, timeout=8,
                                      cookies={"SRCHHPGUSR": "SRCHLANG=en", "_EDGE_S": "mkt=en-us"})
            if not html:
                break
            soup = BeautifulSoup(html.text, "html.parser")
            items = soup.find_all("li", class_="b_algo")
            if not items:
                if self._looks_blocked(html.text):
                    self._blocked.add("bing")
                    self._blocked_at["bing"] = time.time()
                    print(f"{Fore.YELLOW}[!] Bing rate-limited/blocked — pausing Bing queries.")
                break
            for li in items:
                a = li.find("a", href=True)
                if not a:
                    continue
                u = self._bing_redirect(a["href"])
                if not u or self._is_junk(u):
                    continue
                results.append(u)
                if len(results) >= limit:
                    break
            first += 10
        return results

    def search_mojeek(self, query, limit=30):
        if not self._engine_ok("mojeek"):
            return []
        results = []
        s = 0
        while len(results) < limit:
            url = f"https://www.mojeek.com/search?q={quote(query)}&s={s}"
            html = self._engine_fetch("mojeek", url, timeout=8)
            if not html:
                break
            soup = BeautifulSoup(html.text, "html.parser")
            anchors = soup.select("a.ob") or soup.select("h2.title a")
            if not anchors:
                if self._looks_blocked(html.text):
                    self._blocked.add("mojeek")
                    self._blocked_at["mojeek"] = time.time()
                    print(f"{Fore.YELLOW}[!] Mojeek rate-limited/blocked — pausing Mojeek queries.")
                break
            got = 0
            for a in anchors:
                href = a.get("href", "")
                if not href.startswith("http") or self._is_junk(href):
                    continue
                results.append(href)
                got += 1
                if len(results) >= limit:
                    break
            if got == 0:
                break
            s += 10
        return results

    @staticmethod
    def _ddg_redirect(href):
        """Decode a DuckDuckGo uddg= redirect link back to the real URL."""
        m = re.search(r"[?&]uddg=([^&]+)", href)
        if m:
            try:
                return unquote(m.group(1))
            except Exception:
                return None
        if href.startswith("http") and "duckduckgo.com" not in href:
            return href
        return None

    def search_duckduckgo(self, query, limit=30):
        if not self._engine_ok("duckduckgo"):
            return []
        results = []
        s = 0
        while len(results) < limit:
            url = f"https://html.duckduckgo.com/html/?q={quote(query)}&s={s}"
            html = self._engine_fetch("duckduckgo", url, timeout=8)
            if not html:
                break
            soup = BeautifulSoup(html.text, "html.parser")
            anchors = soup.select("a.result__a")
            if not anchors:
                if self._looks_blocked(html.text):
                    self._blocked.add("duckduckgo")
                    self._blocked_at["duckduckgo"] = time.time()
                    print(f"{Fore.YELLOW}[!] DuckDuckGo rate-limited/blocked — pausing DuckDuckGo queries.")
                break
            got = 0
            for a in anchors:
                u = self._ddg_redirect(a.get("href", ""))
                if not u or self._is_junk(u):
                    continue
                results.append(u)
                got += 1
                if len(results) >= limit:
                    break
            if got == 0:
                break
            s += 30
        return results

    def process_dork(self, dork, limit=20):
        """Run one dork through the enabled engines in parallel and merge results."""
        results = set()
        methods = [getattr(self, ENGINES[n]) for n in self._engines if n in ENGINES]
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(methods) or 1) as ex:
            futs = [ex.submit(m, dork, limit) for m in methods]
            for f in concurrent.futures.as_completed(futs):
                try:
                    results.update(f.result())
                except Exception:
                    pass
        return list(results)

    def scan(self, limit=20, dorks=None, max_workers=3):
        """Run all dorks concurrently and yield unique result URLs."""
        dorks = dorks or CAMERA_DORKS
        print(f"{Fore.CYAN}[*] Dorking: {len(dorks)} dorks via "
              f"{', '.join(ENGINE_LABELS.get(n, n.capitalize()) for n in self._engines)}...")
        seen = set()
        done = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {ex.submit(self.process_dork, d, limit): d for d in dorks}
            for f in concurrent.futures.as_completed(futs):
                done += 1
                try:
                    for url in f.result():
                        if url not in seen and self._is_camera(url):
                            seen.add(url)
                            yield url
                except Exception:
                    pass
                sys.stdout.write(f"\r{Fore.YELLOW}[*] Dorks done: {done}/{len(dorks)}  |  {len(seen)} URL(s) found    {Style.RESET_ALL}")
                sys.stdout.flush()
        sys.stdout.write("\r" + " " * 60 + "\r")
        sys.stdout.flush()
        note = f" | blocked: {', '.join(sorted(self._blocked))}" if self._blocked else ""
        print(f"{Fore.CYAN}[*] Dorking done: {len(seen)} URL(s) from {len(dorks)} dorks{note}")


# ══════════════════════════════════════════════════════════════════════════════
# HARVESTER (extract embedded camera URLs from listing/directory pages)
# ══════════════════════════════════════════════════════════════════════════════

IP_URL_RE = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?:/[^\s\"'<>)\]]*)?")
STREAM_PATH_RE = re.compile(
    r"/(?:mjpg|mjpeg|video\.(?:mjpg|cgi)|stream|snapshot|cam_\d|axis-cgi|"
    r"faststream|videostream|cgi-bin/(?:viewer|faststream|stream|mjpg|video|guestimage)|"
    r"nphMotionJpeg|guestimage|ViewerFrame|CgiStart|webcam|live(?:/|\.)|"
    r"image\.jpg|out\.jpg|current\.jpg|\.mjpg)",
    re.I,
)

# Stream/snapshot paths we probe on a discovered camera host.
COMMON_STREAM_PATHS = [
    "/mjpg/video.cgi", "/mjpg/video.mjpg", "/video.cgi", "/videostream.cgi",
    "/axis-cgi/mjpg/video.cgi", "/axis-cgi/jpg/image.cgi",
    "/Streaming/channels/1/httpPreview", "/Streaming/channels/1/picture",
    "/snapshot.cgi", "/snapshot.jpg", "/webcam/video.mjpg",
    "/cgi-bin/viewer/video.jpg", "/cgi-bin/mjpg/video.cgi", "/nphMotionJpeg",
    "/tmpfs/auto.jpg", "/onvif-http/snapshot", "/current.jpg", "/jpg/image.jpg",
    # multi-channel DVR: cam_N.jpg = snapshot, cam_N.cgi = MJPEG stream
    "/cam_1.jpg", "/cam_2.jpg", "/cam_3.jpg", "/cam_4.jpg",
    "/cam_1.cgi", "/cam_2.cgi", "/cam_3.cgi", "/cam_4.cgi",
    "/video.jpg",
]


def probe_stream_paths(base_url):
    """Yield candidate stream URLs by attaching common paths to a camera host."""
    parsed = urlparse(base_url)
    if not parsed.netloc:
        return
    scheme = parsed.scheme or "http"
    for p in COMMON_STREAM_PATHS:
        yield f"{scheme}://{parsed.netloc}{p}"


_CACHE_BUSTER_PARAMS = {"rand", "r", "id", "uniq", "t", "_"}


def normalize_cam_url(url):
    """Dedup key for a camera URL, minus cache-buster params (rand/r/id/uniq)."""
    p = urlparse(url.strip())
    q = "&".join(x for x in p.query.split("&")
                 if x and x.split("=", 1)[0].lower() not in _CACHE_BUSTER_PARAMS)
    return urlunparse((p.scheme, p.netloc, p.path.rstrip("/"), p.params, q, ""))


class Harvester:
    """Extract camera stream URLs embedded in HTML pages."""

    def extract(self, html_text, base_url):
        found = set()

        # Strongest signal: raw IP:port URLs
        for m in IP_URL_RE.findall(html_text):
            found.add(html_unescape(m.rstrip(".,;:!?\"'")))

        # Known camera paths on any host
        soup = BeautifulSoup(html_text, "html.parser")
        for a in soup.find_all("a", href=True):
            href = urljoin(base_url, a["href"])
            if href.startswith("http") and STREAM_PATH_RE.search(href):
                if not any(j in urlparse(href).netloc.lower() for j in JUNK_DOMAINS):
                    found.add(href)

        return found


def harvest_pages(urls, max_pages=150):
    """Fetch promising pages and extract embedded camera URLs."""
    if not urls:
        return []
    urls = list(dict.fromkeys(urls))[:max_pages]
    harvested = set()

    def _work(u):
        html = fetch(u, timeout=12)
        if not html:
            return []
        return Harvester().extract(html.text, u)

    print(f"{Fore.CYAN}[*] Harvesting embedded cameras from {len(urls)} page(s)...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futs = [ex.submit(_work, u) for u in urls]
        for f in concurrent.futures.as_completed(futs):
            try:
                harvested.update(f.result())
            except Exception:
                pass
    return list(harvested)


# ══════════════════════════════════════════════════════════════════════════════
# CAMERA VERIFIER WITH GEOIP
# ══════════════════════════════════════════════════════════════════════════════

class CameraVerifier:
    """Verify camera streams and enrich with GeoIP data."""

    def __init__(self, timeout=6):
        self.timeout = timeout
        self._geo_cache = {}
        self._geo_lock = threading.Lock()

    def get_location(self, host):
        """Lookup geographic location for an IP/hostname (cached)."""
        if host in self._geo_cache:
            return self._geo_cache[host]
        try:
            resp = requests.get(
                f"http://ip-api.com/json/{host}?fields=status,country,city",
                timeout=3,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    loc = f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}"
                    with self._geo_lock:
                        self._geo_cache[host] = loc
                    return loc
        except Exception:
            pass
        return "Unknown"

    @staticmethod
    def _classify(content_type, chunk):
        ct = (content_type or "").lower()
        if "multipart" in ct or "x-mixed-replace" in ct:
            return "LIVE STREAM (MJPEG)"
        # Require the SOI magic — an image/* header with an empty body is dead.
        if chunk.startswith(b"\xff\xd8"):
            return "SNAPSHOT (JPEG)"
        if "video" in ct and chunk:
            return "VIDEO FEED"
        if "image" in ct and chunk.startswith((b"\x89PNG", b"GIF8", b"BM", b"RIFF")):
            return "SNAPSHOT (IMAGE)"
        if chunk.startswith(b"--") and b"Content-Type" in chunk:
            return "LIVE STREAM (MJPEG)"
        return None

    def verify(self, camera):
        """Check if a camera is live and determine its stream type."""
        url = camera["url"]
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            resp = get_session().get(url, headers=headers, timeout=self.timeout, stream=True)
            if resp.status_code != 200:
                return None

            content_type = resp.headers.get("Content-Type", "")
            server = resp.headers.get("Server", "Unknown")
            try:
                chunk = next(resp.iter_content(64))
            except Exception:
                chunk = b""
            resp.close()

            cam_type = self._classify(content_type, chunk)
            if not cam_type:
                return None

            if FILTER_MODE == "STREAM" and not ("STREAM" in cam_type or "VIDEO" in cam_type):
                return None
            if FILTER_MODE == "SNAPSHOT" and "SNAPSHOT" not in cam_type:
                return None

            location = camera.get("location", "Unknown")
            if location == "Unknown" or location.endswith("Unknown, Unknown"):
                host = urlparse(url).hostname
                location = self.get_location(host) if host else "Unknown"

            return {
                "url": url,
                "status": "Live",
                "type": cam_type,
                "server": server,
                "brand": camera.get("brand", "IP Camera"),
                "location": location,
            }
        except Exception:
            return None


# ══════════════════════════════════════════════════════════════════════════════
# REPORTING
# ══════════════════════════════════════════════════════════════════════════════

def write_report(results, fmt="json", outdir="."):
    if not results:
        return None
    os.makedirs(outdir, exist_ok=True)
    stamp = int(time.time())
    base = os.path.join(outdir, f"scan_result_{stamp}")

    if fmt == "csv":
        path = base + ".csv"
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["url", "brand", "location", "type", "server", "status"])
            writer.writeheader()
            for r in results:
                writer.writerow({k: r.get(k, "") for k in writer.fieldnames})
    elif fmt == "html":
        path = base + ".html"
        rows = "\n".join(
            f"<tr><td>{r['type']}</td><td><a href='{r['url']}'>{r['url']}</a></td>"
            f"<td>{r['brand']}</td><td>{r['location']}</td><td>{r['server']}</td></tr>"
            for r in results
        )
        html = (
            "<html><head><meta charset='utf-8'><title>Eyes On Results</title>"
            "<style>body{font-family:sans-serif;margin:2em}table{border-collapse:collapse;width:100%}"
            "th,td{border:1px solid #ccc;padding:6px;text-align:left}th{background:#eee}</style></head>"
            f"<body><h1>Eyes On Scan Results</h1><p>{len(results)} cameras</p>"
            f"<table><tr><th>Type</th><th>URL</th><th>Brand</th><th>Location</th><th>Server</th></tr>"
            f"{rows}</table></body></html>"
        )
        with open(path, "w") as f:
            f.write(html)
    else:
        path = base + ".json"
        with open(path, "w") as f:
            json.dump(results, f, indent=4)

    return path


# ══════════════════════════════════════════════════════════════════════════════
# SCAN ORCHESTRATION
# ══════════════════════════════════════════════════════════════════════════════

def load_dorks(path):
    if not path:
        return CAMERA_DORKS
    try:
        with open(path) as f:
            dorks = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        return list(dict.fromkeys(dorks)) or CAMERA_DORKS
    except Exception:
        print(f"{Fore.YELLOW}[!] Could not read dorks file '{path}', using built-ins.")
        return CAMERA_DORKS


def run_scan(country=None, pages=3, mode="UNIFIED", verify=True, fmt="json",
             outdir=".", threads=40, timeout=6, dorks_file=None, harvest=True,
             harvest_pages_count=150, max_types=None, max_dorks=60,
             engines=None, random_dorks=True):
    """Run a scan and return the live cameras found (streamed as they land)."""
    country_name = COUNTRIES.get(country.upper()) if country else None
    found = []
    seen = set()
    lock = threading.Lock()

    def emit(result):
        """Print a confirmed live camera and record it."""
        if not result:
            return
        if country_name and country_name.lower() not in result["location"].lower():
            return
        found.append(result)
        color = Fore.GREEN if ("STREAM" in result["type"] or "VIDEO" in result["type"]) else Fore.CYAN
        print(f"{color}[+] {Fore.WHITE}{result['url']} "
              f"{Fore.MAGENTA}({result['brand']} | {result['location']} | {result['type']})")

    # ── list-only mode (no verification) ─────────────────────────────────────
    if not verify:
        def collect(url, brand="IP Camera", location="Unknown"):
            key = normalize_cam_url(url)
            if not key:
                return
            with lock:
                if key in seen:
                    return
                seen.add(key)
            emit({"url": key, "brand": brand, "location": location,
                  "type": "-", "server": "-", "status": "Candidate"})

        if mode in ("UNIFIED", "INSECAM"):
            for c in InsecamScraper().scrape(country=country, max_pages=pages, max_types=max_types):
                collect(c["url"], c.get("brand"), c.get("location"))
        if mode in ("UNIFIED", "DORK"):
            dorks = load_dorks(dorks_file)
            if max_dorks and max_dorks > 0 and max_dorks < len(dorks):
                dorks = random.sample(dorks, max_dorks) if random_dorks else dorks[:max_dorks]
            for url in DorkEngine(engines=engines).scan(limit=max(5, pages * 3), dorks=dorks):
                collect(url)
            if harvest:
                for u in harvest_pages(list(seen), max_pages=harvest_pages_count):
                    collect(u)
        print(f"\n{Fore.CYAN}[*] Scan complete. Listed {len(found)} candidate(s).")
        path = write_report(found, fmt=fmt, outdir=outdir)
        if path:
            print(f"{Fore.BLUE}[*] Results saved to {path}")
        return found

    # ── live verification (streaming) ────────────────────────────────────────
    verifier = CameraVerifier(timeout=timeout)
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        pending = []
        inflight_harvest = [0]

        def submit_verify(url, brand="IP Camera", location="Unknown"):
            key = normalize_cam_url(url)
            if not key:
                return False
            with lock:
                if key in seen:
                    return False
                seen.add(key)
                fut = ex.submit(verifier.verify,
                                {"url": key, "brand": brand, "location": location})
                pending.append(fut)
            return True

        def harvest_task(url):
            try:
                html = fetch(url, timeout=12)
                if html:
                    for u in Harvester().extract(html.text, url):
                        submit_verify(u)
                # Some UIs load the stream via JS — probe known paths directly.
                for u in probe_stream_paths(url):
                    submit_verify(u)
            finally:
                with lock:
                    inflight_harvest[0] -= 1

        if mode in ("UNIFIED", "INSECAM"):
            try:
                for c in InsecamScraper().scrape(country=country, max_pages=pages, max_types=max_types):
                    submit_verify(c["url"], c.get("brand"), c.get("location"))
            except Exception as e:
                print(f"{Fore.RED}[-] Insecam error: {e}")

        if mode in ("UNIFIED", "DORK"):
            dorks = load_dorks(dorks_file)
            if max_dorks and max_dorks > 0 and max_dorks < len(dorks):
                dorks = random.sample(dorks, max_dorks) if random_dorks else dorks[:max_dorks]
            dorker = DorkEngine(engines=engines)
            harvested = [0]
            for url in dorker.scan(limit=max(5, pages * 3), dorks=dorks):
                if submit_verify(url) and harvest and harvested[0] < harvest_pages_count:
                    harvested[0] += 1
                    with lock:
                        inflight_harvest[0] += 1
                    ex.submit(harvest_task, url)

        # Drain verification results as they complete (plus any harvest finds)
        while True:
            with lock:
                snapshot = pending
                pending = []
                idle = inflight_harvest[0]
            if not snapshot and idle == 0:
                break
            if snapshot:
                for f in concurrent.futures.as_completed(snapshot):
                    try:
                        emit(f.result())
                    except Exception:
                        pass
            else:
                time.sleep(0.1)

    print(f"\n{Fore.CYAN}[*] Scan complete. Found {len(found)} live camera(s).")
    if not found and FILTER_MODE in ("STREAM", "SNAPSHOT"):
        print(f"{Fore.YELLOW}[!] {FILTER_MODE} mode is strict — most dorked cameras are JPEG "
              f"snapshots. Try Mode = ALL for more results.{Style.RESET_ALL}")
    path = write_report(found, fmt=fmt, outdir=outdir)
    if path:
        print(f"{Fore.BLUE}[*] Results saved to {path}")
    return found


# ══════════════════════════════════════════════════════════════════════════════
# USER INTERFACE
# ══════════════════════════════════════════════════════════════════════════════

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


def center_text(text, width=120):
    """Center text for display (ignoring ANSI color codes)."""
    clean = text
    for code in (Fore.RED, Fore.GREEN, Fore.CYAN, Fore.YELLOW, Fore.WHITE,
                 Fore.BLUE, Fore.MAGENTA, Style.BRIGHT, Style.RESET_ALL):
        clean = clean.replace(code, "")
    padding = max(0, (width - len(clean)) // 2)
    return " " * padding + text


def print_banner():
    """Display the application banner."""
    # Print each line of ASCII art centered
    for line in BANNER.strip().split('\n'):
        print(Fore.RED + center_text(line))
    
    print()
    print(center_text(f"{Style.BRIGHT}{Fore.WHITE}v4.0 | GLOBAL SURVEILLANCE | UNIFIED INTELLIGENCE"))
    print(center_text(f"{Style.BRIGHT}{Fore.YELLOW}Made by Y0oshi | IG: @rde0"))
    print(center_text(Fore.WHITE + '-' * 80))


# ══════════════════════════════════════════════════════════════════════════════
# INTERACTIVE TUI — arrow-key navigation (no slash commands)
# ══════════════════════════════════════════════════════════════════════════════

_GREY_BG = "\x1b[48;5;240m"
_BOLD = "\x1b[1m"
_RESET = "\x1b[0m"
_ARROW_KEYS = {b"[A": "UP", b"[B": "DOWN", b"[C": "RIGHT", b"[D": "LEFT"}


class _RawTerm:
    """Context manager that puts the terminal into cbreak mode."""

    def __enter__(self):
        self.fd = None
        self.old = None
        if HAS_TERMIOS:
            self.fd = sys.stdin.fileno()
            self.old = termios.tcgetattr(self.fd)
            tty.setcbreak(self.fd)
        return self

    def __exit__(self, *exc):
        if self.old is not None:
            termios.tcsetattr(self.fd, termios.TCSADRAIN, self.old)


def _read_key(timeout=0.35):
    """Read one key; returns a token (str) or None on timeout. Requires cbreak mode."""
    if not HAS_TERMIOS:
        return None
    fd = sys.stdin.fileno()
    ready, _, _ = select.select([fd], [], [], timeout)
    if not ready:
        return None
    b = os.read(fd, 1)
    if not b:
        return None
    if b == b"\x1b":
        seq = b""
        for _ in range(2):
            r2, _, _ = select.select([fd], [], [], 0.03)
            if not r2:
                break
            seq += os.read(fd, 1)
        return _ARROW_KEYS.get(seq, "ESC")
    if b in (b"\r", b"\n"):
        return "ENTER"
    if b == b" ":
        return "SPACE"
    if b in (b"\x7f", b"\x08"):
        return "BACKSPACE"
    if b == b"\x03":
        raise KeyboardInterrupt
    if b in (b"q", b"Q"):
        return "q"
    try:
        return b.decode("utf-8")
    except Exception:
        return None


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _visible_len(s):
    """Length of a string with ANSI escape sequences removed."""
    return len(_ANSI_RE.sub("", s))


def _term_cols():
    try:
        return os.get_terminal_size().columns
    except Exception:
        return 120


def _term_rows():
    try:
        return os.get_terminal_size().lines
    except Exception:
        return 24


def _hcenter_pad(text):
    """Leading spaces to horizontally center text (ANSI-safe)."""
    return " " * max(0, (_term_cols() - _visible_len(text)) // 2)


def _center_top(content_lines, used_lines=0):
    """Blank lines to vertically center content_lines below used_lines."""
    return max(0, (_term_rows() - used_lines - content_lines) // 2)


def _menu(options, title=None, top_pad=0):
    """Arrow-key menu; returns the chosen index or None on ESC/q."""
    n = len(options)
    block = (1 if title else 0) + n
    selected = 0
    blink = True
    sys.stdout.write("\n" * top_pad)
    sys.stdout.write("\n" * block)

    def render():
        sys.stdout.write(f"\x1b[{block}A\x1b[J")
        if title:
            sys.stdout.write(_hcenter_pad(title) + title + "\n")
        for i, opt in enumerate(options):
            label = f"   {opt}   "
            line = (_GREY_BG + _BOLD + label + _RESET) if (i == selected and blink) else label
            sys.stdout.write(_hcenter_pad(line) + line + "\n")
        sys.stdout.flush()

    render()
    while True:
        k = _read_key(0.35)
        if k is None:
            blink = not blink
            render()
        elif k == "UP":
            selected = (selected - 1) % n
            blink = True
            render()
        elif k == "DOWN":
            selected = (selected + 1) % n
            blink = True
            render()
        elif k == "ENTER":
            return selected
        elif k in ("ESC", "q"):
            return None


def _clear():
    """Clear the screen and move the cursor home."""
    sys.stdout.write("\x1b[2J\x1b[H")
    sys.stdout.flush()


def _done_button(msg="Scan complete."):
    """Blinking [ DONE ] shown below scan output; returns when Enter is pressed."""
    _menu(["DONE"], title=f"{Fore.GREEN}{msg} — press Enter to return.{Style.RESET_ALL}", top_pad=1)


def _cycle_choice(field, direction):
    choices = field.get("choices", [])
    if not choices:
        return
    cur = field["value"]
    idx = choices.index(cur) if cur in choices else 0
    field["value"] = choices[(idx + direction) % len(choices)]


def _form(fields, title, center=True):
    """Navigable form page. Returns 'submit' when the action is chosen."""
    n = len(fields)
    block = n + 1  # title line + field lines
    selected = 0
    blink = True
    editing = -1
    edit_buf = ""

    def value_str(f):
        if f["kind"] == "checkbox":
            return "[x]" if f["value"] else "[ ]"
        if f["kind"] == "action":
            return ""
        return str(f["value"])

    def line_str(i, f):
        if f["kind"] == "action":
            return f"   [ {f['label']} ]   "
        if i == editing:
            return f"   {f['label']}: {edit_buf}_"
        return f"   {f['label']}: {value_str(f)}"

    def render():
        plain = [title] + [line_str(i, f) for i, f in enumerate(fields)]
        pad = " " * max(0, (_term_cols() - max(_visible_len(x) for x in plain)) // 2)
        sys.stdout.write(f"\x1b[{block}A\x1b[J")
        sys.stdout.write(pad + f"{Fore.CYAN}{title}{Style.RESET_ALL}" + "\n")
        for i, f in enumerate(fields):
            txt = line_str(i, f)
            if i == selected and blink:
                txt = _GREY_BG + _BOLD + txt + _RESET
            sys.stdout.write(pad + txt + "\n")
        sys.stdout.flush()

    if center:
        sys.stdout.write("\n" * _center_top(block))
    sys.stdout.write("\n" * block)
    render()
    while True:
        k = _read_key(0.35)
        if k is None:
            blink = not blink
            render()
            continue

        if editing >= 0:
            f = fields[editing]
            if k == "ENTER":
                if f["kind"] == "number":
                    try:
                        v = int(edit_buf)
                    except ValueError:
                        v = f.get("value", f.get("min", 1))
                    f["value"] = max(f.get("min", 1), min(f.get("max", v), v))
                else:
                    f["value"] = edit_buf
                editing = -1
                render()
            elif k == "BACKSPACE":
                edit_buf = edit_buf[:-1]
                render()
            elif k == "ESC":
                editing = -1
                render()
            elif isinstance(k, str) and len(k) == 1:
                if f["kind"] == "number" and not k.isdigit():
                    continue
                edit_buf += k
                render()
            continue

        f = fields[selected]
        if k == "UP":
            selected = (selected - 1) % n
            blink = True
            render()
        elif k == "DOWN":
            selected = (selected + 1) % n
            blink = True
            render()
        elif k == "SPACE":
            if f["kind"] == "checkbox":
                f["value"] = not f["value"]
                render()
        elif k == "LEFT":
            if f["kind"] == "choice":
                _cycle_choice(f, -1)
                render()
        elif k == "RIGHT":
            if f["kind"] == "choice":
                _cycle_choice(f, 1)
                render()
        elif k == "ENTER":
            if f["kind"] == "action":
                return "submit"
            if f["kind"] == "checkbox":
                f["value"] = not f["value"]
                render()
            elif f["kind"] == "choice":
                _cycle_choice(f, 1)
                render()
            elif f["kind"] in ("number", "text"):
                editing = selected
                edit_buf = "" if f["kind"] == "number" else str(f["value"])
                render()
        elif k in ("ESC", "q"):
            return None


def _scan_page(settings):
    global FILTER_MODE
    mode_now = FILTER_MODE if FILTER_MODE in ("ALL", "STREAM", "SNAPSHOT") else "ALL"
    fields = [
        {"kind": "number", "label": "Pages", "value": 3, "min": 1, "max": 100},
        {"kind": "number", "label": "Dorks", "value": settings.get("max_dorks", 60),
         "min": 1, "max": len(CAMERA_DORKS)},
        {"kind": "checkbox", "label": "Random select dorks", "value": settings.get("random_dorks", True)},
        {"kind": "choice", "label": "Mode", "value": mode_now, "choices": ["ALL", "STREAM", "SNAPSHOT"]},
        {"kind": "action", "label": "START SCAN"},
    ]
    if _form(fields, "  SCAN  —  DORK SEARCH") == "submit":
        pages = fields[0]["value"]
        maxd = fields[1]["value"]
        rand = fields[2]["value"]
        FILTER_MODE = fields[3]["value"]
        settings["random_dorks"] = rand
        settings["max_dorks"] = maxd
        _clear()
        print(f"\n{Fore.YELLOW}[*] Dork scan: {maxd} dorks, {pages} page(s), "
              f"mode={FILTER_MODE}, random={rand}{Style.RESET_ALL}")
        run_scan(pages=pages, mode="DORK", fmt=settings.get("format", "json"),
                 outdir=settings.get("outdir", "."), max_dorks=maxd,
                 random_dorks=rand, engines=settings.get("engines"))
        _done_button()


def _scrape_page(settings):
    global FILTER_MODE
    mode_now = FILTER_MODE if FILTER_MODE in ("ALL", "STREAM", "SNAPSHOT") else "ALL"
    fields = [
        {"kind": "number", "label": "Pages", "value": 3, "min": 1, "max": 100},
        {"kind": "text", "label": "Country (code or ALL)", "value": "ALL"},
        {"kind": "choice", "label": "Mode", "value": mode_now, "choices": ["ALL", "STREAM", "SNAPSHOT"]},
        {"kind": "action", "label": "START SCRAPE"},
    ]
    if _form(fields, "  SCRAPE INSECAM") == "submit":
        pages = fields[0]["value"]
        country = fields[1]["value"].strip().upper()
        note = ""
        if country in ("", "ALL"):
            country = None
        elif country not in COUNTRIES:
            note = "unknown country — scanning all"
            country = None
        FILTER_MODE = fields[2]["value"]
        _clear()
        if note:
            print(f"\n{Fore.RED}[-] {note}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}[*] Insecam scrape: {pages} page(s), "
              f"country={country or 'ALL'}, mode={FILTER_MODE}{Style.RESET_ALL}")
        run_scan(country=country, pages=pages, mode="INSECAM",
                 fmt=settings.get("format", "json"), outdir=settings.get("outdir", "."))
        _done_button("Scrape complete.")


def _options_page(settings):
    names = ["yahoo", "bing", "mojeek", "duckduckgo"]
    engines = settings.get("engines", names)
    fields = [
        {"kind": "text", "label": "JSON export path", "value": settings.get("outdir", ".")},
    ]
    for n in names:
        fields.append({"kind": "checkbox", "label": ENGINE_LABELS[n], "value": n in engines})
    fields.append({"kind": "action", "label": "SAVE"})
    if _form(fields, "  OPTIONS") == "submit":
        settings["outdir"] = fields[0]["value"].strip() or "."
        chosen = [n for n, f in zip(names, fields[1:1 + len(names)]) if f["value"]]
        settings["engines"] = chosen or ["yahoo"]
        save_config(settings)
        _clear()
        print(f"{Fore.GREEN}[+] Saved: path='{settings['outdir']}', "
              f"engines={', '.join(settings['engines'])}{Style.RESET_ALL}")
        _done_button("Settings saved.")


def interactive_mode(cfg):
    """Arrow-key interactive TUI (no slash commands)."""
    global FILTER_MODE

    # Non-Unix terminal (no termios): fall back to a minimal prompt loop.
    if not HAS_TERMIOS:
        while True:
            print(f"\n{Fore.WHITE}1. SCAN   2. SCRAPE INSECAM   3. OPTIONS   4. EXIT{Style.RESET_ALL}")
            c = input("> ").strip()
            if c == "1":
                pages = int(input("Pages: ") or 3)
                maxd = int(input(f"Dorks (max {len(CAMERA_DORKS)}): ") or 60)
                run_scan(pages=pages, mode="DORK", max_dorks=maxd)
            elif c == "2":
                pages = int(input("Pages: ") or 3)
                country = input("Country (or ALL): ").strip().upper()
                run_scan(country=None if country in ("", "ALL") else country,
                         pages=pages, mode="INSECAM")
            elif c == "4":
                break
        return

    settings = {
        "format": cfg.get("format", "json"),
        "outdir": cfg.get("outdir", "."),
        "engines": cfg.get("engines", ["yahoo", "bing", "mojeek", "duckduckgo"]),
        "random_dorks": cfg.get("random_dorks", True),
        "max_dorks": cfg.get("max_dorks", 60),
    }

    banner_h = len(BANNER.strip().split("\n")) + 4  # art + blank + subtitle + madeby + rule
    home_block = 5  # title + 4 options
    home_pad = _center_top(home_block, used_lines=banner_h)

    try:
        with _RawTerm():
            while True:
                _clear()
                print_banner()
                choice = _menu(["SCAN", "SCRAPE INSECAM", "OPTIONS", "EXIT"],
                               title=f"{Fore.CYAN}Choose an action (↑/↓ + Enter):{Style.RESET_ALL}",
                               top_pad=home_pad)
                if choice is None or choice == 3:
                    break
                _clear()
                if choice == 0:
                    _scan_page(settings)
                elif choice == 1:
                    _scrape_page(settings)
                elif choice == 2:
                    _options_page(settings)
    except KeyboardInterrupt:
        pass
    _clear()
    print(f"{Fore.RED}Goodbye.{Style.RESET_ALL}")


def parse_args():
    p = argparse.ArgumentParser(
        prog="eyeson",
        description="Project Eyes On - public IP camera reconnaissance (educational use only)",
    )
    p.add_argument("--scrape", type=int, metavar="N", help="scrape Insecam directory (N pages per type)")
    p.add_argument("--scan", type=int, metavar="N", help="run dork search (N pages)")
    p.add_argument("--unified", type=int, metavar="N", help="run both Insecam + dork search (N pages)")
    p.add_argument("-c", "--country", metavar="CC", help="target country code (e.g. US, JP, RU)")
    p.add_argument("-m", "--mode", choices=["ALL", "STREAM", "SNAPSHOT"], help="filter by stream type")
    p.add_argument("-f", "--format", choices=["json", "csv", "html"], default="json", help="report format")
    p.add_argument("-o", "--output", default=".", help="output directory for reports")
    p.add_argument("--no-verify", action="store_true", help="skip live verification (list candidates only)")
    p.add_argument("--no-harvest", action="store_true", help="disable embedded-URL harvesting")
    p.add_argument("--harvest-pages", type=int, default=150, help="max pages to harvest (default 150)")
    p.add_argument("--threads", type=int, default=40, help="verification concurrency (default 40)")
    p.add_argument("--timeout", type=int, default=6, help="per-request timeout in seconds (default 6)")
    p.add_argument("--dorks", metavar="FILE", help="custom dorks file (one dork per line)")
    p.add_argument("--max-dorks", type=int, default=60, help="max dorks to run (0 = all; default 60)")
    p.add_argument("--max-types", type=int, help="limit number of Insecam types to crawl")
    p.add_argument("--list-countries", action="store_true", help="list supported country codes and exit")
    return p.parse_args()


def main():
    global FILTER_MODE
    cfg = load_config()
    args = parse_args()

    if args.list_countries:
        for code, name in sorted(COUNTRIES.items()):
            print(f"{code}\t{name}")
        return

    if args.country:
        code = args.country.upper()
        if code not in COUNTRIES:
            print(f"{Fore.RED}[-] Invalid country code: {args.country}")
            return
        args.country = code

    if args.mode:
        FILTER_MODE = args.mode

    # Determine scan mode from flags
    mode = None
    pages = None
    if args.unified:
        mode, pages = "UNIFIED", args.unified
    elif args.scan and args.scrape:
        mode, pages = "UNIFIED", max(args.scan, args.scrape)
    elif args.scan:
        mode, pages = "DORK", args.scan
    elif args.scrape:
        mode, pages = "INSECAM", args.scrape

    if mode is None:
        interactive_mode(cfg)
        return

    run_scan(
        country=args.country,
        pages=pages,
        mode=mode,
        verify=not args.no_verify,
        fmt=args.format or cfg.get("format", "json"),
        outdir=args.output,
        threads=args.threads,
        timeout=args.timeout,
        dorks_file=args.dorks,
        harvest=not args.no_harvest,
        harvest_pages_count=args.harvest_pages,
        max_types=args.max_types,
        max_dorks=args.max_dorks,
    )


if __name__ == "__main__":
    main()
