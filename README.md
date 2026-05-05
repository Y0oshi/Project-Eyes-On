# UNSLOPPED FROM AI - Project Eyes On v3.0 (Global Surveillance)
**Originally "Coded" by: Y0oshi (AI CHATBOT), edited by cosmicstations to actually be somewhat usable**

![Banner](https://img.shields.io/badge/Status-Active-brightgreen) ![Python](https://img.shields.io/badge/Python-3.x-blue) ![License](https://img.shields.io/badge/License-MIT-green)

![Screenshot](screenshot.png)

## Overview
**Project Eyes On** is a hyper-fast, multi-threaded surveillance tool designed to locate open IP cameras across the globe. It combines two powerful engines:
1.  **Directory Scraper**: Harvests feeds from Insecam.
2.  **Deep Web Dorking**: Uses Google & Yahoo search dorks to find hidden cameras not listed in public directories.

## Features
-   **Parallel Engine**: Queries **Yahoo** and **Startpage** simultaneously for maximum speed and results.
-   **GeoIP Enrichment**: Automatically resolves camera IP locations to **City, Country** (e.g., "New York, United States").
-   **Smart Deduplication**: Merges results from multiple engines to ensure unique feeds.
-   **Direct Connection**: Optimized for speed without unreliable proxies.
-   **Country Targeting**: Target specific regions (e.g., `/country US`, `/country RU`).
-   **Live Verification**: Automatically detects stream types (MJPEG, JPEG, Video).

### Prerequisites
-   Python 3.x
-   Pip

### macOS / Linux / Windows
1. **Clone the Repository**:
```
git clone https://github.com/Y0oshi/Project-Eyes-On.git
cd Project-Eyes-On
python eyes.py
```

or
```
python3 eyes.py
```

## Usage

### Commands
| Command | Description | Example |
| :--- | :--- | :--- |
| `/scrape [Pages]` | Scrape Insecam (Public Directory) | `/scrape 5` |
| `/scan [Pages]` | Google Dork Search (Deep Web) | `/scan 50` |
| `/country [Code]` | Target Logic (e.g., US, JP, RU) | `/country US` |
| `/mode [Type]` | Filter (ALL, STREAM, SNAPSHOT) | `/mode STREAM` |
| `/exit` | Quit Tool | `/exit` |
