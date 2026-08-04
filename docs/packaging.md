# AIVAS Packaging Guide

## PyPI (pip install aivas)

### One-time setup — create your PyPI account and token

1. **Create account:** go to https://pypi.org/account/register/  
   (email verification required — check inbox)

2. **Create API token:** Account Settings → API tokens → "Add API token"  
   - Token name: `aivas-upload`  
   - Scope: **Entire account** (first upload only; restrict to `aivas` after)  
   - Click "Add token" — copy the token immediately, it is shown only once.

3. **Save token** in `~/.pypirc` (this is on your local machine, never commit this file):
   ```ini
   [distutils]
   index-servers = pypi

   [pypi]
   username = __token__
   password = pypi-AgAAA...YOUR_TOKEN_HERE
   ```
   ```bash
   chmod 600 ~/.pypirc
   ```

### Upload

```bash
# Install twine if not already present
pip install twine --break-system-packages

# Upload (uses ~/.pypirc automatically)
cd /home/cyberpunk/aivas
twine upload dist/*

# Expected output:
#   Uploading aivas-0.1.0-py3-none-any.whl
#   Uploading aivas-0.1.0.tar.gz
#   View at: https://pypi.org/project/aivas/0.1.0/
```

### After upload — install anywhere

```bash
pip install aivas                    # standard
pipx install aivas                   # isolated (recommended on Kali/Ubuntu)
pip install aivas --break-system-packages   # Kali without pipx
```

### Future versions (bump + re-upload)

```bash
# 1. Edit pyproject.toml: version = "0.1.1"
# 2. Rebuild frontend if changed: cd frontend && npm run build && cd ..
# 3. Copy new dist to bundled static: cp frontend/dist/* aivas/server/static/
# 4. python3 -m build
# 5. twine upload dist/aivas-0.1.1*
```

---

## Launchpad PPA (sudo apt install aivas)

### One-time setup — create the AIVAS PPA

1. Go to https://launchpad.net/~malila-arch  
2. Click "Create a new PPA"  
3. Name: `aivas`  
4. Display name: `AIVAS — AI Vulnerability Scanner`  
5. Description: `Ubuntu packaging for AIVAS (aivas.cli terminal UI + web UI)`  
6. Click "Activate"

PPA URL will be: `ppa:malila-arch/aivas`

### Install build tools (one-time)

```bash
sudo apt install devscripts debhelper dput
```

### Update the pre-built wheel when code changes

Every time you push a new version, rebuild the wheel and update `debian/prebuilt/`:

```bash
cd /home/cyberpunk/aivas

# If frontend changed:
cd frontend && npm run build && cd ..
cp -r frontend/dist/* aivas/server/static/

# Rebuild wheel
python3 -m build
cp dist/aivas-0.1.0-py3-none-any.whl debian/prebuilt/
```

### Build the signed source package

```bash
# For Ubuntu 24.04 (Noble):
./scripts/build-source-package.sh noble

# For Ubuntu 22.04 (Jammy):
./scripts/build-source-package.sh jammy
```

This builds in `/tmp/aivas-launchpad-build/` and signs with your GPG key (`bmalila87@gmail.com`).

### Upload to Launchpad

```bash
./scripts/upload-ppa.sh noble
# Then for Jammy if needed:
./scripts/upload-ppa.sh jammy
```

Build status: https://launchpad.net/~malila-arch/+archive/ubuntu/aivas/+builds  
(Takes 15–30 min on Launchpad's build farm.)

### After the build finishes — users install with

```bash
sudo add-apt-repository ppa:malila-arch/aivas
sudo apt update
sudo apt install aivas
```

### Bump version for a new release

1. Edit `pyproject.toml`: `version = "0.1.1"`
2. Edit `debian/changelog` — add entry at the top:
   ```
   aivas (0.1.1-1~noble1) noble; urgency=medium

     * What changed here.

    -- Baraka Malila <bmalila87@gmail.com>  DATE HERE
   ```
   Generate the date with: `date -R`
3. Rebuild wheel, copy to `debian/prebuilt/`, run build + upload scripts.

---

## Kali quick-install (tomorrow's test)

```bash
# Option A — from PyPI (after upload):
pipx install aivas

# Option B — from local wheel (no internet needed):
pip install /path/to/aivas-0.1.0-py3-none-any.whl --break-system-packages

# Option C — using install.sh (handles Kali PEP 668 automatically):
bash install.sh

# Launch:
aivas serve --open    # web UI in browser at http://127.0.0.1:8000
aivas                 # terminal UI
```
