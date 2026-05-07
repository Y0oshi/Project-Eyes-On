#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  Wired Eyes Search v1.0                                                      ║
║  Public IP Camera Finder/Scraper Tool                                        ║
║  Created by Y0oshi                                                           ║ 
║  Forked by: auski                                                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

A surveillance tool for discovering publicly accessible IP cameras using the options:
  - Insecam directory scraping
  - Multi-engine dorking (Yahoo + Startpage)
  - GeoIP location enrichment
  - Live stream verification
"""

import requests
import threading
import time
import random
import json
import sys
import os
import concurrent.futures
from urllib.parse import urlparse, unquote
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

init(autoreset=True)

#random is seperate
USER_AGENTS =  {
    "WINDOWS_CHROME": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "MAC_SAFARI": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.2 Safari/605.1.15",
    "WINDOWS_FIREFOX": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "LINUX_CHROME": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
    "IPHONE_SAFARI": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1"
}

INSECAM_URL = "http://www.insecam.org/en"

data_map = {
    "colors": ["red", "green", "blue"],
    "numbers": ["one", "two", "three"]
}

CAMERA_DORKS = {
    "AXIS":
    [
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
        'tilt intitle:"Live View / - AXIS" | inurl:view/view.shtml',
        'intitle:"AXIS 240 Camera Server" intext:"server push" -help',
        'intitle:"Live View /- AXIS" |inurl:view/view.shtml OR inurl:view/indexFrame.shtml |intitle:"MJPG Live Demo" |intext:"Select preset position"',
        'allintitle:Axis 2.10 OR 2.12 OR 2.30 OR 2.31 OR 2.32 OR 2.33 OR 2.34 OR 2.40 OR 2.42 OR 2.43 "Network Camera"',
        'intitle:"Live View/ — AXIS"',
        'intitle:"Live View/ — AX|S"',
        'intitle:"Live View / - AXIS 706W"',
        'AXIS Camera exploit'
    ],

    "HIKVISION":
    [
        'intitle:"Hikvision Web Cameras"',
        'inurl:"/doc/page/login.asp" intext:"Hikvision"',
        'intitle:"Hikvision" inurl:"login.asp"',
        'inurl:"/onvif-http/snapshot?auth="',
        'product:"Hikvision IP Camera"'
    ],

    "MOBOTIX":
    [
        'inurl:"/cgi-bin/guestimage.html"',
        'inurl:"/control/faststream.jpg"',
        'intitle:"MOBOTIX" inurl:"/control/userimage.html"',
        '(intitle:MOBOTIX intitle:PDAS) | (intitle:MOBOTIX intitle:Seiten)',
        'inurl:/pda/index.html +camera'
    ],

    "FORSCAM":
    [
        'intitle:"Foscam" inurl:"login.htm"',
        'inurl:"/videostream.cgi?user="',
        'intitle:"Foscam" inurl:"/live.htm"'
    ],

    "PARASONIC":
    [
        'intitle:"Foscam" inurl:"login.htm"',
        'inurl:"/videostream.cgi?user="',
        'intitle:"Foscam" inurl:"/live.htm"'
    ],

    "DLINK":
    [
        'intitle:"D-Link" inurl:"/video.htm"',
        'inurl:"/mjpg/video.cgi" intitle:"D-Link"',
        'intitle:"D-Link DCS-"',
        'inurl:"/eng/admin/adv_audiovideo.cgi"'
    ],

    "SONY":
    [
        'intitle:"sony network camera snc-pl"',
        'intitle:"Sony" inurl:"/home/homeJ.html"',
        'intitle:"SNC-RZ30" -demo',
        'intitle:"sony network camera snc-ml"',
        'inurl:"/image/webcam.jpg" intitle:"Sony"',
        'intitle:snc-220 inurl:home/',
        'intitle:snc-cs3 inurl:home/',
        'intitle:snc-r230 inurl:home/'
    ],

    "CANON":
    [
        'intitle:"Network Camera VB-M600"',
        'inurl:"/sample/LvAppl/lvappl.htm"',
        'inurl:"lvappl.htm"',
        'inurl:"/view.shtml" "camera"'
    ],

    "VIVOTEK":
    [
        'server:VVTK-HTTP-Server',
        'inurl:"/cgi-bin/viewer/video.jpg"'
    ],

    "WEBCAM":
    [
        'intitle:"webcamXP 5"',
        'intitle:"webcam 7"',
        'intext:"powered by webcamXP 5"',
        'inurl:"/cam_1.jpg" intitle:"webcamXP"',
        'intitle:"webcam 7" inurl:"/gallery.html"',
        'intitle:"webcamXP 5" -download',
        'intitle:"webcam 7" inurl:"8080" -intext:"8080"',
        'intitle:"webcamXP 5" inurl:8080 \'Live\'',
        'intitle:"WEBCAM 7 " -inurl:/admin.html',
        'intitle:"webcam 7" inurl::8080',
        'intitle:"webcam 7" inurl::8081',
        'intitle:"webcam 7" inurl::8000',
        'intitle:"webcamXP 5" inurl::8080',
        'intitle:"Webcam" inurl:WebCam.htm',
        'intitle:webcamxp inurl:8080'
    ],

    "DAHUA":
    [
        'intitle:"Dahua IP Camera" inurl:/login',
        'inurl:dahua inurl:view/view.shtml',
        'intitle:"Dahua" inurl:"/cgi-bin/rpc.cgi?action=login"',
        'intext:"Dahua" intitle:"Network Camera" inurl:main.cgi'
    ],

    "REOLINK":
    [
        'intitle:"Reolink" inurl:view',
        'intitle:"Reolink Camera" inurl:login',
        'intitle:"Reolink" inurl:snapshot.cgi',
        'intitle:"Reolink" inurl:/cgi-bin/',
        'inurl:"/Reolink" intitle:"Live" -shop -store'
    ],

    "UNIFI":
    [
        'intitle:"UniFi Video" inurl:login',
        'intitle:"UniFi Protect" inurl:7443',
        'inurl:snap.jpg intext:"ubiquiti"',
        'intitle:"UniFi Protect" inurl:/protect/live',
        'inurl:/cc/view.html intext:"unifi"'
    ],

    "BLUE_IRIS":
    [
        'intitle:"Blue Iris Login"',
        'intitle:"Blue Iris Remote View"'
    ],

    "ANDROID_WEBCAM":
    [
        'inurl:"videomgr.html"',
        'intitle:"Android IP Webcam"'
    ],

    "CGI":
    [
        'inurl:"/cgi-bin/live.cgi"',
        'inurl:"/cgi-bin/stream.cgi"',
        'inurl:"/cgi-bin/snapshot.cgi"',
        'inurl:"/cgi-bin/camctrl.cgi"',
        'intitle:"Index of /DCIM"',
        'inurl:"logo.bmp" intitle:"Webcam"',
        'inurl:"snapshot.cgi?user="',
        'inurl:"/axis-cgi/mjpg"'
    ],

    "GEOVISION":
    [
        'intitle:"GeoVision WebCam Server" inurl:/WebCam',
        'intitle:"GeoVision" inurl:/login.htm',
        'inurl:/geovision/ login',
        'intitle:"GeoVision MultiCam Surveillance System" live view',
        'inurl:geovision filetype:txt "password"'
    ],

    "AVIGILON":
    [
        'intitle:"Avigilon Control Center" inurl:/login',
        'inurl:/avigilon/viewer',
        'intitle:"Avigilon" intext:"live video"',
        'inurl:/avigilon/webclient/'
    ],

    "VIVOTEK":
    [
        'intitle:"Vivotek Camera" inurl:/viewer',
        'intitle:"Vivotek" intext:"live view"',
        'intitle:"Vivotek" inurl:/cgi-bin/',
        'inurl:/vivotek/ rtsp'
    ],

    "ZONEMINDER":
    [
        'intitle:"ZoneMinder" inurl:/zm/index.php',
        'intext:"ZoneMinder" inurl:view=event',
        'inurl:/zoneminder/cgi-bin/nph-zms'
    ],

    "SHODAN_SEARCH":
    [
        'product:"Hikvision IP Camera"',
        'title:"IPCam Client"',
        'http.title:"WEB VIEW" dahua',
        'intitle:"Blue Iris Login"',
    ],

    "TOSHIBA":
    [
        'intitle:"Toshiba Network Camera"',
        'inurl:"/user/index.html" intitle:"Toshiba"',
        'intitle:"Toshiba Network Camera" user Login',
    ],

    "LINKSYS":
    [
        'intitle:"Linksys Viewer - Login" -inurl:mainFrame',
        'inurl:"main.cgi?next_file=main_fs.htm"'
    ],

    "TP_LINK":
    [
        'intitle:"TP-LINK IP-Camera"'
    ],

    "OTHER":
    [
        'intitle:"Live View" inurl:"login.cgi"',
        'intitle:"IP Camera" inurl:"login.html"',
        'inurl:"/view/index.shtml" -inurl:axis',
        'inurl:"/view/view.shtml" -inurl:axis',
        'inurl:"/main.cgi?next_file=main_fs.htm"',
        'intitle:"netcam watcher"',
        'intitle:"Network Camera NetworkCamera"',
        'inurl:"snapshot.cgi?user="',
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
        'intitle:"Live View / - AXIS"',
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
        'intitle:"Device(" AND intext:"Network Camera" AND "language:" "AND "Password"',
        'intitle:"yawcam" inurl:":8081"',
        'intitle:"iGuard Fingerprint Security System"',
        'intitle:"Edr1680 remote viewer"',
        'intitle:"NetCam Live Image" -.edu -.gov -johnny.ihackstuff.com',
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
        'intitle:"Weather Wing WS-2"'
    ]
}

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
Wired Eyes Search
"""

FOUND_CAMERAS = []

MODES = ['DORK', 'INSECAM'] 
TYPES = ['STREAM', 'SNAPSHOT']

COUNTRIES = {
    "US": "United States", 
    "JP": "Japan", 
    "IT": "Italy", 
    "DE": "Germany",
    "RU": "Russia", 
    "FR": "France", 
    "KR": "Korea", 
    "TW": "Taiwan",
    "NO": "Norway", 
    "CA": "Canada", 
    "GB": "United Kingdom", 
    "NL": "Netherlands",
    "SE": "Sweden", 
    "ES": "Spain", 
    "CH": "Switzerland", 
    "AT": "Austria",
    "PL": "Poland", 
    "CZ": "Czech Republic", 
    "RO": "Romania", 
    "BR": "Brazil"
}

SETTINGS = {
    "Country": None,
    "Filter": ["ALL"],
    "Pages": 5,
    "Types": [],
    "Mode": ["DORK"],
    "Type": ["STREAM"],
    "Agent": "RANDOM",
    "Logging": False
}

# ══════════════════════════════════════════════════════════════════════════════
# FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

class insecam_scraper:    
    def build_url(self, country=None, page=10):
        if country:
            return f"{INSECAM_URL}/bycountry/{country}/?page={page}"
        return f"{INSECAM_URL}/byrating/?page={page}"
    
    def scrape_page(self, url, agent = "RANDOM"):
        cameras = []
        try:
            if agent in USER_AGENTS:
                headers = {'User-Agent': USER_AGENTS[agent]}
            else:
                headers = {'User-Agent': random.choice(list(USER_AGENTS.values()))}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                for img in soup.find_all('img'):
                    src = img.get('src', '')
                    title = img.get('title', '')
                    
                    junk_terms = ['static', 'insecam', 'yandex', 'google', 'facebook', 'twitter', 
                                 'instagram', 'tiktok', 'analytics', 'doubleclick', 'counter']
                    
                    if 'http' in src and not any(term in src.lower() for term in junk_terms):
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
    
    def scrape(self, country=None, max_pages=5, agent="RANDOM"):
        all_cameras = []
        print(f"{Fore.CYAN}[*] Scraping Insecam ({max_pages} pages)...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            urls = [self.build_url(country, page) for page in range(1, max_pages + 1)]
            results = executor.map(self.scrape_page, urls, agent)
            
            for cameras in results:
                all_cameras.extend(cameras)
        
        unique = {cam['url']: cam for cam in all_cameras}
        print(f"{Fore.GREEN}[+] Found {len(unique)} unique feeds from Insecam")

        return list(unique.values())

class search_engine_dorks:    
    def search_yahoo(self, query, limit=50, agent = "RANDOM"):
        results = []
        start = 1
        
        while len(results) < limit:
            time.sleep(random.uniform(1.0, 2.0))
            
            try:
                if agent in USER_AGENTS:
                    headers = {
                        'User-Agent': USER_AGENTS[agent],
                        'Accept': 'text/html,application/xhtml+xml',
                        'Referer': 'https://www.google.com/'
                    }
                else:
                    headers = {
                        'User-Agent': random.choice(list(USER_AGENTS.values())),
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
    
    def search_startpage(self, query, limit=50, agent = "RANDOM"):
        results = []
        seen = set()
        
        try:
            if agent in USER_AGENTS:
                headers = {'User-Agent': USER_AGENTS[agent]}
            else:
                headers = {'User-Agent': random.choice(list(USER_AGENTS.values()))}

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
    
    def process_dork(self, dork, limit=20, agent="RANDOM"):
        all_results = []
        seen = set()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            yahoo_future = executor.submit(self.search_yahoo, dork, limit)
            startpage_future = executor.submit(self.search_startpage, dork, limit, agent)
            
            for future in concurrent.futures.as_completed([yahoo_future, startpage_future]):
                try:
                    for result in future.result():
                        if result['url'] not in seen:
                            seen.add(result['url'])
                            all_results.append(result)
                except:
                    pass
        return all_results
    
    def scan(self, limit=20, agent="RANDOM", dorks=["ALL"]):
        if dorks == ["ALL"]:
            print(f"{Fore.CYAN}[*] Running {len(CAMERA_DORKS)} camera dork types... with {sum(len(values) for values in CAMERA_DORKS.values())} dorks")
        else:
            print(f"{Fore.CYAN}[*] Running {len(dorks)} camera dork types...") #maybe in the future add the total dork count

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:

            if dorks == ["ALL"]:
                future_map = {executor.submit(self.process_dork, dork, limit, agent): dork for dork in CAMERA_DORKS.items()}
            else:
                future_map = {
                    executor.submit(self.process_dork, dork_item, limit, agent): dork_item
                    for key in dorks
                        if key in CAMERA_DORKS
                            for dork_item in CAMERA_DORKS[key]
                }
            
            for future in concurrent.futures.as_completed(future_map):
                try:
                    for result in future.result():
                        yield result
                except:
                    pass

class camera_verifier:    
    def get_location(self, host):
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
    
    def verify(self, camera, got_type=['STREAM'], agent="RANDOM"):
        url = camera['url']

        if not url.startswith("http://"):
            return None

        if agent in USER_AGENTS:
            headers = {'User-Agent': USER_AGENTS[agent]}
        else:
            headers = {'User-Agent': random.choice(list(USER_AGENTS.values()))}

        response = requests.get(url, timeout=6, stream=True, headers=headers)
   
        if response.status_code == 200:
            content_type = response.headers.get('Content-Type', '').lower()
            server = response.headers.get('Server', 'Unknown')
            
            cam_type = None
            if 'multipart' in content_type or 'x-mixed-replace' in content_type:
                cam_type = 'LIVE STREAM (MJPEG)'
            elif 'image' in content_type:
                cam_type = 'SNAPSHOT (JPEG)'
            elif 'video' in content_type:
                cam_type = 'VIDEO FEED'
            
            if cam_type:
                if 'STREAM' in got_type  and 'STREAM' not in cam_type:
                    return None
                if 'SNAPSHOT' in got_type and 'SNAPSHOT' not in cam_type:
                    return None
                
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
            else:
                return {
                    'url': url,
                    'status': 'Live',
                    'type': "UNKNOWN",
                    'server': "UNKNOWN",
                    'brand': "UNKNOWN",
                    'location': "UNKNOWN"
                }
        else:
            return {
                'url': url,
                'status': 'Live',
                'type': "UNKNOWN",
                'server': "UNKNOWN",
                'brand': "UNKNOWN",
                'location': "UNKNOWN"
            }
        
        return None

def center_text(text, width=120):
    clean = text
    for code in [Fore.RED, Fore.GREEN, Fore.CYAN, Fore.YELLOW, Fore.WHITE, Fore.BLUE, Fore.MAGENTA, Style.BRIGHT, Style.RESET_ALL]:
        clean = clean.replace(code, '')
    padding = max(0, (width - len(clean)) // 2)
    return ' ' * padding + text

def print_banner(banner):
    for line in banner.strip().split('\n'):
        print(Fore.RED + center_text(line))
    
    #print()
    print(center_text(f"{Style.BRIGHT}{Fore.WHITE}v1.0"))
    print(center_text(f"{Style.BRIGHT}{Fore.YELLOW}Forked by auski"))
    print(center_text(f"{Style.BRIGHT}{Fore.YELLOW}Original by Y0oshi"))
    print(center_text(Fore.WHITE + '-' * 80))

    print(center_text(Fore.BLUE + "help for commands"))

def run_scan(country=None, got_filter=['ALL'], pages=100, got_type=['STREAM'], mode=['DORK'], agent="RANDOM", logging=False):
    global FOUND_CAMERAS
    
    #settings here?
    insecam = insecam_scraper()
    dorker = search_engine_dorks()
    verifier = camera_verifier()
    
    seen_urls = set()
    
    print(f"\n{Style.BRIGHT}{Fore.YELLOW}" + center_text(f"=== SCANNING ({mode}) ==="))
    print()
    
    def verify_and_print(camera, agent):
        if camera['url'] in seen_urls:
            return

        seen_urls.add(camera['url'])
        
        result = verifier.verify(camera, got_type=got_type, agent=agent)
        #print(result)
        if result:
            color = Fore.GREEN if 'STREAM' in result['type'] else Fore.CYAN
            print(f"\r{color}[+] {Fore.WHITE}{result['url']} {Fore.MAGENTA}({result['brand']} | {result['location']})")
            FOUND_CAMS.append(result)
    
    stop_spinner = False
    def spinner():
        while not stop_spinner:
            for dots in ['.  ', '.. ', '...']:
                if stop_spinner: break
                sys.stdout.write(f"\r{Fore.YELLOW}[*] Still searching{dots}{Style.RESET_ALL}   ")
                sys.stdout.flush()
                time.sleep(0.5)

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        if 'INSECAM' in mode:
            FOUND_CAMERAS = insecam.scrape(country=country, max_pages=pages, agent=agent)
            executor.map(verify_and_print, FOUND_CAMERAS, agent)
        
        if 'DORK' in mode:
            t = threading.Thread(target=spinner)
            t.start()
            try:
                for camera in dorker.scan(limit=pages * 10, agent=agent, dorks=got_filter): #scan(self, limit=20, agent="RANDOM", dorks=["ALL"])
                    executor.submit(verify_and_print, camera, agent)
            finally:
                stop_spinner = True
                t.join()
                sys.stdout.write('\r' + ' ' * 50 + '\r')

    print(f"\n{Fore.CYAN}[*] Scan complete. Found {len(FOUND_CAMERAS)} live cameras.")
    
    if logging == True:
        filename = f"scan_result_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(FOUND_CAMERAS, f, indent=4)
        print(f"{Fore.BLUE}[*] Results saved to {filename}")

def resize_terminal(rows=40, cols=125):
    """Resize the terminal window to fit content."""
    sys.stdout.write(f"\x1b[8;{rows};{cols}t")

def main():        
    resize_terminal()
    print_banner(BANNER)
        
    while True:
        try:
            cmd = input(f"\n{Fore.RED}> {Fore.WHITE}").strip()

            if not cmd:
                continue
            
            parts = cmd.split()
            command = parts[0].lower()
            
            if command == 'help':
                print(f"\n{Fore.WHITE}Commands:\n")
                print(f"{Fore.CYAN} clear {Fore.WHITE} - clears screen")
                print(f"{Fore.CYAN} pages {Fore.BLUE}[pages]{Fore.WHITE} - set the total pages to go through")
                print(f"{Fore.CYAN} country {Fore.BLUE}[code/list]{Fore.WHITE} - Set the target country")
                print(f"{Fore.CYAN} agent {Fore.BLUE}[type/list]{Fore.WHITE} - Set the user agent")
                print(f"{Fore.CYAN} mode {Fore.BLUE} [type/list]{Fore.WHITE} - Modes: dork, insecam")
                print(f"{Fore.CYAN} type {Fore.BLUE} [type/list]{Fore.WHITE} - Types: stream, snapshot")
                #print(f"{Fore.CYAN} threads {Fore.BLUE}[count]{Fore.WHITE} - Set the threads count")
                #add a timeout for scan time?
                print(f"{Fore.CYAN} filter {Fore.BLUE} [type/all/list]{Fore.WHITE} - Filter through camera dorks and types")
                print(f"{Fore.CYAN} log {Fore.BLUE}[true/false]{Fore.WHITE} - Prints found results into a file")
                print(f"{Fore.CYAN} scan {Fore.WHITE} - start scan")
                print(f"{Fore.CYAN} exit {Fore.WHITE} - quit")
            elif command == 'scan':
                #country=None, Filter=['ALL'], pages=100, type=['STREAM'], mode=['DORK'], agent="RANDOM", logging=False
                run_scan(country=SETTINGS["Country"], got_filter=SETTINGS["Filter"], got_type=SETTINGS["Type"], pages=SETTINGS["Pages"], agent=SETTINGS["Agent"], mode=SETTINGS["Mode"], logging=SETTINGS["Logging"])
            elif command == 'pages' or command == 'page':
                pages = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 3

                print(f"{Fore.GREEN}[+] Pages set to {pages}")
                SETTINGS["Pages"] = pages 
            elif command == 'country':
                if len(parts) > 1:
                    code = parts[1].upper()
                    if code in COUNTRIES:
                        SETTINGS["Country"] = code
                        print(f"\n{Fore.GREEN}[+] Country Target set to {code} ({COUNTRIES[code]})")
                    elif code == "LIST":
                        for code, country in COUNTRIES.items():
                            print(f"\n{Fore.BLUE} {code} {Fore.GREEN} {country} {Fore.WHITE}")
                    elif code == "NONE":
                        SETTINGS["Country"] = None
                        print(f"\n{Fore.GREEN}[+] Country Target set to None")
                    else:
                        print(f"\n{Fore.RED}[-] Invalid country code")
                else:
                    print(f"\n{Fore.YELLOW}[*] Current: {SETTINGS["Country"]}")
            elif command == 'mode' or command == 'modes':
                if len(parts) > 1:
                    mode = parts[1].upper()
                    if mode in MODES:
                        if mode in SETTINGS["Mode"]:
                            if len(SETTINGS["Mode"]) != 1:
                                SETTINGS["Mode"].remove(mode)
                                print(f"\n{Fore.RED}[+] removed mode {parts[1]}")
                            else:
                                print(f"\n{Fore.RED}[-] cannot remove mode {parts[1]} since it's the only one")
                        else:
                            SETTINGS["Mode"].append(mode)
                        print(f"\n{Fore.GREEN}[+] Filter set to {SETTINGS["Mode"]}")
                    elif mode == "LIST":
                        for got_mode in MODES:
                            print(f"\n{Fore.BLUE} {got_mode} {Fore.WHITE}")
                    else:
                        print(f"\n{Fore.RED}[-] Invalid mode")
                else:
                    print(f"\n{Fore.YELLOW}[*] Current: {SETTINGS["Mode"]}")  
            elif command == 'type' or command == 'types':
                if len(parts) > 1:
                    type_got = parts[1].upper()
                    if type_got in TYPES:
                        if type_got in SETTINGS["Type"]:
                            if len(SETTINGS["Type"]) != 1:
                                SETTINGS["Type"].remove(type_got)
                                print(f"\n{Fore.RED}[+] removed type {parts[1]}")
                            else:
                                print(f"\n{Fore.RED}[-] cannot remove type {parts[1]} since it's the only one")
                        else:
                            SETTINGS["Type"].append(type_got)
                        print(f"\n{Fore.GREEN}[+] Type set to {SETTINGS["Type"]}")
                    elif type_got == "LIST":
                        for got_type in TYPES:
                            print(f"\n{Fore.BLUE} {got_type} {Fore.WHITE}")
                    else:
                        print(f"\n{Fore.RED}[-] Invalid type")
                else:
                    print(f"\n{Fore.YELLOW}[*] Current: {SETTINGS["Type"]}")   
            elif command == 'filter':          
                if len(parts) > 1:
                    filter_got = parts[1].upper()
                    if filter_got in CAMERA_DORKS:
                        if SETTINGS["Filter"] == ["ALL"]:
                            SETTINGS["Filter"].clear()

                        if filter_got in SETTINGS["Filter"]:
                            if len(SETTINGS["Filter"]) != 1:
                                SETTINGS["Filter"].remove(filter_got)
                                print(f"\n{Fore.RED}[+] removed filter {parts[1]}")
                            else:
                                print(f"\n{Fore.RED}[-] cannot remove filter {parts[1]} since it's the only one")
                        else:
                            SETTINGS["Filter"].append(filter_got)
                        
                        print(f"\n{Fore.GREEN}[+] Filter set to {SETTINGS["Filter"]}")
                    elif filter_got == "ALL":
                        SETTINGS["Filter"].clear()
                        SETTINGS["Filter"].append("ALL")
                        print(f"\n{Fore.GREEN}[+] Filter set to {SETTINGS["Filter"]}")
                    elif filter_got == "LIST":
                        for got_type in CAMERA_DORKS:
                            print(f"\n{Fore.BLUE} {got_type} {Fore.WHITE}")
                    else:
                        print(f"\n{Fore.RED}[-] Invalid filter")
                else:
                    print(f"\n{Fore.YELLOW}[*] Current: {SETTINGS["Filter"]}")   
            elif command == 'agent' or command == 'agents':
                if len(parts) > 1:   
                    agent = parts[1].upper()
                    if agent in USER_AGENTS or agent == "RANDOM":
                        SETTINGS["Agent"] = agent
                        print(f"\n{Fore.GREEN}[+] Filter set to {SETTINGS["Agent"]}")
                    elif agent == "LIST":
                        for get_agent in USER_AGENTS:
                            print(f"\n{Fore.WHITE} {get_agent} {Fore.WHITE}")  

                        print(f"\n{Fore.WHITE} RANDOM {Fore.WHITE}")           
                    else:
                        print(f"\n{Fore.RED}[-] Invalid agent")
                else:
                    print(f"\n{Fore.YELLOW}[*] Current: {SETTINGS["Agent"]}")    
            elif command == 'log':
                if len(parts) > 1:
                    log = parts[1].upper()

                    if log in ["TRUE", "FALSE"]:
                        answer = (log == "TRUE")
                        SETTINGS["Logging"] = answer

                        print(f"\n{Fore.GREEN}[+] Logging set to {SETTINGS["Logging"]}")
                    else:
                        print(f"\n{Fore.RED}[-] Invalid log setting")
                else:
                    print(f"\n{Fore.YELLOW}[*] set: {SETTINGS["Logging"]}")   
            elif command == 'clear':
                os.system('cls' if os.name == 'nt' else 'clear')
                print_banner(BANNER)
            elif command == 'exit' or command == "quit":
                sys.exit(0)
            else:
                print(f"\n{Fore.RED}[?] Uknown Command: " + parts[0])
        
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}Aborted.")
            break
        except Exception as e:
            print(f"\n{Fore.RED}[-] Error: {e}")

if __name__ == '__main__':
    main()
