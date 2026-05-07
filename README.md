# Wired Eyes Search v1.0 (Global Surveillance)
**Maintained by Auski**
**Created by Y0oshi**

![Screenshot](screenshot.png)

## Overview
**Wired Eyes Search** is a multi-threaded surveillance tool designed to locate open IP cameras. It combines two options:
1.  **Directory Scraper**: Harvests feeds from Insecam.
2.  **Deep Web Dorking**: Uses Google & Yahoo search dorks to find hidden cameras not listed in public directories.

## Features:
-   **Parallel Engine**: Queries **Yahoo** and **Startpage** simultaneously for maximum speed and results.
-   **GeoIP Enrichment**: Automatically resolves camera IP locations to **City, Country** (e.g., "New York, United States").
-   **Smart Deduplication**: Merges results from multiple engines to ensure unique feeds.
-   **Direct Connection**: Optimized for speed without unreliable proxies.
-   **Country Targeting**: Target specific regions (e.g., `/country US`, `/country RU`).
-   **Live Verification**: Automatically detects stream types (MJPEG, JPEG, Video).

### Prerequisites
-   Python 3.x
-   Pip

## Libraries required by pip
-  requests
-  beautifulsoup4
-  colorama

### macOS / Linux / Windows
1. **Download Libraries using pip**
```
pip install beautifulsoup4
pip install requests
pip install colorama
```

2. **Clone the Repository**:
```
git clone https://github.com/Y0oshi/Project-Eyes-On.git
cd Project-Eyes-On
```

**Options**
From here you have two options, either 1. to install to command line or 2. use python directly

1. **Install the Command**:
The installer script sets up and creates the `eyeson` command.

```
chmod +x install.sh
sudo ./install.sh
```

2. **Run the file in python**

```
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
| `help` | list commands | `help` |
| `clear` | clears the screen | `clear` |
| `pages` | set the total pages | `pages 50` |
| `country [code/list]` | choose a country to target (e.g., US, JP, RU) | `country US` |
| `agent [type/list]` | set the agent the scraper uses | `agent random` |
| `mode [type]` | modes: dork, insecam | `mode dork` |
| `type [type]` | types: stream, snapshot | `type stream` |
| `filter [type]` | filter through the camera types | `filter all` |
| `log [type]` | writes results into a file, true/false | `log true` |
| `scan` | starts the scan | `scan` |
| `exit` | quit | `exit` |
