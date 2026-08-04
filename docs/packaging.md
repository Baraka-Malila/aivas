# AIVAS Packaging Guide

## Local install (pip)

```bash
# From repo root
python3 -m build          # creates dist/aivas-*.whl and dist/aivas-*.tar.gz
pip install dist/aivas-0.1.0-py3-none-any.whl

# Or, directly editable during development:
pip install -e .
```

## Kali / Debian / Ubuntu — install.sh

```bash
bash install.sh           # user install (no root, uses pipx if available)
bash install.sh --system  # system-wide (uses --break-system-packages)
```

## PyPI upload

Requires a PyPI account and API token at https://pypi.org/manage/account/token/

```bash
pip install twine                                    # one-time setup
python3 -m build                                     # rebuild if needed
twine upload dist/*                                  # prompts for token
# Username: __token__
# Password: pypi-AgAAAA...  (paste your token)
```

After upload, users can install with:
```bash
pip install aivas
# or on Kali/Ubuntu:
pipx install aivas
```

## Web UI

After install, start the web UI:

```bash
aivas serve --open       # opens http://127.0.0.1:8000 in browser
aivas serve --port 9000  # custom port
```

## Launchpad PPA

### Prerequisites
- Launchpad account: https://launchpad.net/
- GPG key uploaded to Launchpad and keyserver
- `dput`, `devscripts`, `debhelper`, `dh-python` installed

### Build the source package

```bash
# Install build tools
sudo apt install devscripts debhelper dh-python python3-all

# From repo root — builds the signed .changes file
debuild -S -sa

# This produces (in parent directory):
#   aivas_0.1.0-1.dsc
#   aivas_0.1.0-1.tar.gz
#   aivas_0.1.0-1_source.changes  (signed with your GPG key)
```

### Upload to PPA

```bash
# Replace YOUR_LAUNCHPAD_ID with your Launchpad username
dput ppa:YOUR_LAUNCHPAD_ID/aivas ../aivas_0.1.0-1_source.changes
```

### dput configuration (~/.dput.cf)

```ini
[aivas-ppa]
fqdn = ppa.launchpad.net
method = ftp
incoming = ~YOUR_LAUNCHPAD_ID/ubuntu/aivas
login = anonymous
allow_unsigned_uploads = 0
```

### After upload

Launchpad build queue typically takes 15–30 minutes.  
Users install from your PPA with:

```bash
sudo add-apt-repository ppa:YOUR_LAUNCHPAD_ID/aivas
sudo apt update
sudo apt install aivas
```

### Version bumps

Edit `debian/changelog` with `dch -i` to increment version, then rebuild and re-upload.

```bash
dch -i "Fixed: describe changes here"
debuild -S -sa
dput ppa:YOUR_LAUNCHPAD_ID/aivas ../aivas_0.1.1-1_source.changes
```

### Target Ubuntu series

The `debian/changelog` series (currently `noble`) controls which Ubuntu
version Launchpad builds for.  To publish for multiple series, copy the
changelog entry with `dch -b`, change `noble` to e.g. `jammy`, bump the
Debian revision to `-2`, rebuild, and re-upload.

```bash
dch -b "Rebuild for jammy"
# Edit changelog: change noble → jammy, version to 0.1.0-2~jammy
debuild -S -sa
dput ppa:YOUR_LAUNCHPAD_ID/aivas ../aivas_0.1.0-2~jammy_source.changes
```
