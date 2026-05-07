#!/bin/bash

# Eyes On - Installation Script (v3.0)
# Made by Y0oshi

if [ "$EUID" -ne 0 ]
  then echo "[!] Please run as root (sudo ./install.sh)"
  exit
fi

# Get the absolute path of the current directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "[*] Creating Virtual Environment..."
python3 -m venv "$DIR/venv"

echo "[*] Installing Dependencies into venv..."
"$DIR/venv/bin/pip" install --upgrade pip
"$DIR/venv/bin/pip" install -r "$DIR/requirements.txt"

echo "[*] Setting up 'eyeson' command..."

# Create a wrapper script that uses the venv python
WRAPPER="$DIR/eyeson_runner"
cat <<EOF > "$WRAPPER"
#!/bin/bash
exec "$DIR/venv/bin/python3" "$DIR/eyes.py" "\$@"
EOF

chmod +x "$WRAPPER"

# Create symlink in /usr/local/bin
ln -sf "$WRAPPER" /usr/local/bin/eyeson

echo "[+] Installation Complete!"
echo "[*] Virtual environment created in $DIR/venv"
echo "[*] You can now run 'sudo eyeson' from anywhere."
