#!/bin/bash
echo "[*] Installing FrameStalker locally..."

# Check if pip is already the latest version and inform user
LATEST_PIP=$(pip install pip --dry-run --disable-pip-version-check 2>/dev/null | grep -oP '(?<=from versions: ).*' | grep -oP '[0-9.]+(?=,)' | tail -1)
CURRENT_PIP=$(pip --version | awk '{print $2}')

if [ "$CURRENT_PIP" != "$LATEST_PIP" ]; then
    echo "There is a newer version of pip available. It is recommended to upgrade in the event of any errors..."
else
    echo "pip is already at the latest version ($CURRENT_PIP)."
fi

echo "Installing required packages - PyQt5 and scapy"

# Install packages
pip install PyQt5 scapy

INSTALL_DIR="$HOME/.local/share/FrameStalker"
DESKTOP_DIR="$HOME/.local/share/applications"
DESKTOP_FILE="$DESKTOP_DIR/framestalker.desktop"
ICON_PATH="$INSTALL_DIR/assets/icon.png"
LAUNCH_PATH="$INSTALL_DIR/launch.sh"


# Create install dirs
mkdir -p "$INSTALL_DIR"
mkdir -p "$DESKTOP_DIR"

# Copy everything except install.sh and git files
rsync -av --exclude='install.sh' --exclude='.git' --exclude='.gitignore' ./ "$INSTALL_DIR"


# Create .desktop launcher with full launch path
cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Name=FrameStalker
Exec=bash -c "cd '$INSTALL_DIR' && sudo python3 -m frame_stalker_gui"
Icon=$ICON_PATH
Terminal=true
Type=Application
Categories=Utility;Network;Wireless Attacks
EOF

chmod +x "$DESKTOP_FILE"

echo "[✓] Installed to $INSTALL_DIR"
echo "[✓] Launcher created at $DESKTOP_FILE"
echo "→ To see the app on your desktop you may need to log out/in or run: update-desktop-database"
echo "FrameStalker can now be launched from the menu or terminal!"
