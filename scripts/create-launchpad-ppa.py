#!/usr/bin/env python3
"""
Create the AIVAS PPA on Launchpad via launchpadlib.
Run once. Opens a browser page to authorize — paste the URL if it doesn't open.

Usage:
    python3 scripts/create-launchpad-ppa.py
"""
import os
from pathlib import Path
from launchpadlib.launchpad import Launchpad

LP_LOGIN   = "malila-arch"
PPA_NAME   = "aivas"
PPA_TITLE  = "AIVAS — AI Vulnerability Scanner"
PPA_DESC   = (
    "Ubuntu packaging for AIVAS (AI-Assisted Network Vulnerability Assessment System). "
    "Provides the 'aivas' CLI: terminal UI, web UI, offline CVE database, "
    "bilingual English/Swahili narration."
)

LP_DIR = Path.home() / ".launchpadlib"
LP_DIR.mkdir(exist_ok=True)
CREDS_FILE = LP_DIR / f"{LP_LOGIN}-credentials.txt"

print("Connecting to Launchpad (browser window will open for authorization)...")
lp = Launchpad.login_with(
    application_name="aivas-ppa-setup",
    service_root="production",
    launchpadlib_dir=str(LP_DIR),
    credentials_file=str(CREDS_FILE),
    version="devel",
)

me = lp.people[LP_LOGIN]
print(f"Logged in as: {me.display_name} ({me.name})")

# Check if PPA already exists
existing = [a for a in me.ppas if a.name == PPA_NAME]
if existing:
    ppa = existing[0]
    print(f"PPA already exists: {ppa.web_link}")
else:
    print(f"Creating PPA '{PPA_NAME}'...")
    ppa = me.createPPA(
        name=PPA_NAME,
        displayname=PPA_TITLE,
        description=PPA_DESC,
    )
    print(f"PPA created: {ppa.web_link}")

print()
print("Users install with:")
print(f"  sudo add-apt-repository ppa:{LP_LOGIN}/{PPA_NAME}")
print(f"  sudo apt update && sudo apt install aivas")
print()
print("Now run: ./scripts/upload-ppa.sh noble")
