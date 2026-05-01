#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# LevarG — One-Shot Setup Runner
# Installs every dependency/prerequisite and prepares the app.
# Usage:  chmod +x setup.sh && ./setup.sh
#
# Supported: Ubuntu, Debian, Kali (native & WSL), macOS
# ──────────────────────────────────────────────────────────────

# ── Helpers ──────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
fail()  { echo -e "${RED}[✗]${NC} $*"; }
need()  { command -v "$1" &>/dev/null; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LEVARG_HOME="${LEVARG_TOOLS_HOME:-$HOME/.levarg}"
WORDLISTS_DIR="$LEVARG_HOME/wordlists"
TEMPLATES_DIR="$LEVARG_HOME/templates"
NODE_MAJOR=20
ERRORS=0

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║       LevarG — Full Environment Setup            ║${NC}"
echo -e "${GREEN}║       LEVELACE SENTINEL LLC                      ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# ── Detect OS / WSL / Distro ─────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"
IS_WSL=false
IS_KALI=false
DISTRO="unknown"

if [[ "$OS" == "Linux" ]]; then
  # WSL detection
  if grep -qiE '(microsoft|wsl)' /proc/version 2>/dev/null; then
    IS_WSL=true
  fi
  # Distro detection
  if [[ -f /etc/os-release ]]; then
    DISTRO="$(. /etc/os-release && echo "${ID:-unknown}")"
  fi
  if [[ "$DISTRO" == "kali" ]]; then
    IS_KALI=true
  fi
fi

is_linux()  { [[ "$OS" == "Linux" ]]; }
is_mac()    { [[ "$OS" == "Darwin" ]]; }

info "Detected: $OS / $ARCH / distro=$DISTRO / WSL=$IS_WSL"

if ! is_linux && ! is_mac; then
  fail "This script supports Linux and macOS. For Windows, use WSL2."
  exit 1
fi

# ── Package manager helpers ──────────────────────────────────
APT_UPDATED=false

apt_update_once() {
  if [[ "$APT_UPDATED" == false ]]; then
    info "Updating package lists..."
    sudo apt-get update -qq 2>/dev/null || warn "apt-get update had issues"
    APT_UPDATED=true
  fi
}

apt_install() {
  apt_update_once
  sudo apt-get install -y "$@" 2>/dev/null
}

brew_install() {
  brew install "$@" 2>/dev/null || true
}

# ── 1. System prerequisites (git, curl, unzip, build-essential) ──
info "Checking system prerequisites..."
PKGS=()
for cmd in git curl unzip wget; do
  if ! need "$cmd"; then PKGS+=("$cmd"); fi
done

if is_linux; then
  if ! need gcc; then PKGS+=(build-essential); fi
  if ! need python3; then PKGS+=(python3); fi
  if (( ${#PKGS[@]} > 0 )); then
    info "Installing: ${PKGS[*]}"
    apt_install "${PKGS[@]}" || {
      warn "Some prerequisites failed to install"
      ((ERRORS++))
    }
  fi
elif is_mac; then
  if ! need brew; then
    info "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" || {
      fail "Homebrew install failed"; ((ERRORS++))
    }
  fi
  if (( ${#PKGS[@]} > 0 )); then
    info "Installing: ${PKGS[*]}"
    brew_install "${PKGS[@]}"
  fi
fi
ok "System prerequisites ready"

# ── 2. Node.js (via nvm) ────────────────────────────────────
info "Checking Node.js..."
export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"

# Install nvm if not present
if [[ ! -d "$NVM_DIR" ]] || [[ ! -s "$NVM_DIR/nvm.sh" ]]; then
  info "Installing nvm..."
  NVM_INSTALL="/tmp/nvm_install_$$.sh"
  if curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh -o "$NVM_INSTALL"; then
    bash "$NVM_INSTALL" || { fail "nvm install script failed"; ((ERRORS++)); }
    rm -f "$NVM_INSTALL"
  else
    fail "nvm download failed"
    ((ERRORS++))
  fi
fi

# Source nvm — it's a shell function, not a binary
if [[ -s "$NVM_DIR/nvm.sh" ]]; then
  source "$NVM_DIR/nvm.sh"
fi
# Also load bash_completion if available
if [[ -s "$NVM_DIR/bash_completion" ]]; then
  source "$NVM_DIR/bash_completion"
fi

# Verify nvm is available (it's a function, so use `type`)
if ! type nvm &>/dev/null; then
  fail "nvm is not available after sourcing. Manual fix:"
  fail "  export NVM_DIR=\"\$HOME/.nvm\""
  fail "  [ -s \"\$NVM_DIR/nvm.sh\" ] && source \"\$NVM_DIR/nvm.sh\""
  fail "  Then re-run this script."
  exit 1
fi

# Ensure nvm sourcing is in the user's shell rc file
# Handles both bash and zsh (Kali defaults to zsh)
NVM_SOURCE_BLOCK='export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"'

for rcfile in "$HOME/.bashrc" "$HOME/.zshrc"; do
  if [[ -f "$rcfile" ]] && ! grep -q 'NVM_DIR' "$rcfile" 2>/dev/null; then
    info "Adding nvm to $rcfile"
    {
      echo ""
      echo "# nvm (added by LevarG setup)"
      echo "$NVM_SOURCE_BLOCK"
    } >> "$rcfile"
  fi
done
# If zshrc doesn't exist but the user's default shell is zsh, create it
if [[ "$(basename "${SHELL:-bash}")" == "zsh" ]] && [[ ! -f "$HOME/.zshrc" ]]; then
  info "Creating ~/.zshrc with nvm sourcing (Kali/zsh detected)"
  {
    echo "# nvm (added by LevarG setup)"
    echo "$NVM_SOURCE_BLOCK"
  } > "$HOME/.zshrc"
fi

# Install or use the correct Node version
CURRENT_NODE="$(node -v 2>/dev/null || echo 'none')"
if [[ "$CURRENT_NODE" != v${NODE_MAJOR}.* ]]; then
  info "Installing Node.js $NODE_MAJOR (current: $CURRENT_NODE)..."
  nvm install "$NODE_MAJOR" || {
    fail "Failed to install Node.js $NODE_MAJOR via nvm"
    exit 1
  }
  nvm use "$NODE_MAJOR"
else
  ok "Node.js $CURRENT_NODE already installed"
fi
nvm alias default "$NODE_MAJOR" 2>/dev/null || true

# Verify node & npm are working
if ! need node || ! need npm; then
  fail "node/npm not found after nvm setup. Something went wrong."
  exit 1
fi
ok "Node.js $(node -v) / npm $(npm -v) ready"

# ── 3. Go (for ProjectDiscovery tools / pdtm) ───────────────
info "Checking Go..."
if ! need go; then
  GO_VERSION="1.23.9"
  case "$ARCH" in
    x86_64|amd64) GO_ARCH="amd64" ;;
    aarch64|arm64) GO_ARCH="arm64" ;;
    *) warn "Unsupported arch for Go: $ARCH — skipping Go install"; GO_ARCH="" ;;
  esac
  if [[ -n "$GO_ARCH" ]]; then
    if is_linux; then GO_OS="linux"; else GO_OS="darwin"; fi
    GO_TAR="go${GO_VERSION}.${GO_OS}-${GO_ARCH}.tar.gz"
    info "Installing Go $GO_VERSION..."
    if curl -fsSL "https://go.dev/dl/$GO_TAR" -o "/tmp/$GO_TAR"; then
      sudo rm -rf /usr/local/go
      sudo tar -C /usr/local -xzf "/tmp/$GO_TAR"
      rm -f "/tmp/$GO_TAR"
      export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
      ok "Go $(go version | awk '{print $3}') installed"
    else
      warn "Go download failed — some tools will be unavailable"
      ((ERRORS++))
    fi
  fi
else
  export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
  ok "Go $(go version | awk '{print $3}') already installed"
fi

# Ensure GOPATH/bin is in PATH for this session and future shells
if ! echo "$PATH" | grep -q "$HOME/go/bin"; then
  export PATH="$HOME/go/bin:$PATH"
fi
for rcfile in "$HOME/.bashrc" "$HOME/.zshrc"; do
  if [[ -f "$rcfile" ]] && ! grep -q 'go/bin' "$rcfile" 2>/dev/null; then
    echo 'export PATH="$HOME/go/bin:/usr/local/go/bin:$PATH"' >> "$rcfile"
  fi
done

# ── 4. Ollama (local AI — free, no API key) ──────────────────
info "Checking Ollama..."
if ! need ollama; then
  info "Installing Ollama..."
  if $IS_WSL; then
    # WSL often lacks systemd — the install script may fail on the service step.
    # Try the script first; if it fails, fall back to a manual binary install.
    OLLAMA_INSTALL="/tmp/ollama_install_$$.sh"
    if curl -fsSL https://ollama.com/install.sh -o "$OLLAMA_INSTALL" 2>/dev/null && sh "$OLLAMA_INSTALL" 2>/dev/null; then
      rm -f "$OLLAMA_INSTALL"
      ok "Ollama installed"
    else
      rm -f "$OLLAMA_INSTALL"
      warn "Ollama install script failed (common on WSL without systemd)"
      info "  Trying manual binary install..."
      case "$ARCH" in
        x86_64|amd64) OLLAMA_BIN="ollama-linux-amd64" ;;
        aarch64|arm64) OLLAMA_BIN="ollama-linux-arm64" ;;
        *) OLLAMA_BIN="" ;;
      esac
      if [[ -n "$OLLAMA_BIN" ]]; then
        mkdir -p "$HOME/bin"
        if curl -fsSL "https://ollama.com/download/$OLLAMA_BIN" -o "$HOME/bin/ollama" 2>/dev/null; then
          chmod +x "$HOME/bin/ollama"
          export PATH="$HOME/bin:$PATH"
          ok "Ollama installed to ~/bin/ollama"
          info "  Tip: run 'ollama serve' manually in a separate terminal before starting LevarG"
        else
          warn "Ollama binary download failed — AI features will be unavailable"
          warn "  You can install Ollama later: https://ollama.com/download"
          ((ERRORS++))
        fi
      else
        warn "Ollama: unsupported arch $ARCH — skipping"
        ((ERRORS++))
      fi
    fi
  else
    # Native Linux / macOS
    OLLAMA_INSTALL="/tmp/ollama_install_$$.sh"
    if curl -fsSL https://ollama.com/install.sh -o "$OLLAMA_INSTALL" 2>/dev/null && sh "$OLLAMA_INSTALL" 2>/dev/null; then
      rm -f "$OLLAMA_INSTALL"
      ok "Ollama installed"
    else
      rm -f "$OLLAMA_INSTALL"
      warn "Ollama install failed — AI features will be unavailable"
      warn "  You can install later: https://ollama.com/download"
      ((ERRORS++))
    fi
  fi
else
  ok "Ollama already installed"
fi

# Pull default model if not present
if need ollama; then
  if ollama list 2>/dev/null | grep -q "llama3.2"; then
    ok "Model llama3.2 already pulled"
  else
    info "Pulling llama3.2 model (~2 GB)..."
    ollama pull llama3.2 2>/dev/null || warn "Could not pull model — run 'ollama pull llama3.2' later"
  fi
fi

# ── 5. pdtm (ProjectDiscovery Tool Manager) ──────────────────
info "Checking pdtm..."
if ! need pdtm; then
  if need go; then
    info "Installing pdtm via go install..."
    go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest 2>/dev/null
  fi
  if ! need pdtm; then
    # Fallback: download binary
    case "${OS}_${ARCH}" in
      Linux_x86_64|Linux_amd64)   PDTM_BIN="pdtm_linux_amd64.zip" ;;
      Linux_aarch64|Linux_arm64)  PDTM_BIN="pdtm_linux_arm64.zip" ;;
      Darwin_x86_64|Darwin_amd64) PDTM_BIN="pdtm_macOS_amd64.zip" ;;
      Darwin_arm64)               PDTM_BIN="pdtm_macOS_arm64.zip" ;;
      *) PDTM_BIN="" ;;
    esac
    if [[ -n "$PDTM_BIN" ]]; then
      info "Installing pdtm from binary..."
      curl -fsSL "https://github.com/projectdiscovery/pdtm/releases/latest/download/$PDTM_BIN" -o /tmp/pdtm.zip 2>/dev/null \
        && sudo unzip -o /tmp/pdtm.zip -d /usr/local/bin 2>/dev/null \
        && rm -f /tmp/pdtm.zip
    fi
  fi
  if need pdtm; then ok "pdtm installed"; else warn "pdtm install failed — install manually"; ((ERRORS++)); fi
else
  ok "pdtm already installed"
fi

# ── 6. Core security tools via pdtm ─────────────────────────
PD_TOOLS=(subfinder httpx nuclei katana naabu dnsx tlsx interactsh-client uncover)

info "Checking ProjectDiscovery tools..."
if need pdtm; then
  for tool in "${PD_TOOLS[@]}"; do
    if ! need "$tool"; then
      info "  Installing $tool via pdtm..."
      pdtm -install "$tool" 2>/dev/null || warn "  Failed to install $tool"
    else
      ok "  $tool already installed"
    fi
  done
else
  warn "pdtm not available — skipping PD tools batch install"
fi

# ── 7. Other security tools (apt/brew) ───────────────────────
info "Checking additional tools..."

install_tool() {
  local name="$1" apt_pkg="${2:-$1}" brew_pkg="${3:-$1}"
  if need "$name"; then ok "  $name already installed"; return; fi
  info "  Installing $name..."
  if is_linux; then
    apt_install "$apt_pkg" || warn "  apt install $apt_pkg failed"
  elif is_mac; then
    brew_install "$brew_pkg" || warn "  brew install $brew_pkg failed"
  fi
  if need "$name"; then ok "  $name installed"; else warn "  $name not found after install attempt"; fi
}

install_tool nmap
install_tool ffuf
install_tool dirb
install_tool nikto
install_tool sqlmap
install_tool whatweb
install_tool gobuster

# Go-installable tools not in pdtm
if need go; then
  for gotool in "github.com/lc/gau/v2/cmd/gau@latest" "github.com/hahwul/dalfox/v2@latest" "github.com/OJ/gobuster/v3@latest"; do
    TOOL_BIN="$(basename "${gotool%%@*}")"
    if ! need "$TOOL_BIN"; then
      info "  Installing $TOOL_BIN via go install..."
      go install -v "$gotool" 2>/dev/null || warn "  go install $TOOL_BIN failed"
    else
      ok "  $TOOL_BIN already installed"
    fi
  done
else
  warn "Go not available — skipping go-installable tools (gau, dalfox, gobuster)"
fi

# ── 8. Chromium / Puppeteer dependencies ─────────────────────
info "Checking Chromium dependencies for Puppeteer..."
if is_linux; then
  # Build an array of candidate deps. Different distros/releases
  # name the same library differently (t64 suffix on newer Debian/Ubuntu,
  # plain names on Kali and older releases).  We try each variant.
  CHROME_DEPS_MODERN=(libnss3 libatk1.0-0t64 libatk-bridge2.0-0t64 libcups2t64
                      libxdamage1 libxrandr2 libgbm1 libpango-1.0-0 libcairo2
                      libasound2t64 libxshmfence1)
  CHROME_DEPS_LEGACY=(libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2
                      libxdamage1 libxrandr2 libgbm1 libpango-1.0-0 libcairo2
                      libasound2 libxshmfence1)

  MISSING_DEPS=()

  # On Kali (Debian rolling) the t64-suffixed packages often don't exist;
  # try the legacy names first, fall back to modern names.
  if $IS_KALI; then
    CANDIDATES=("${CHROME_DEPS_LEGACY[@]}")
  else
    CANDIDATES=("${CHROME_DEPS_MODERN[@]}")
  fi

  for dep in "${CANDIDATES[@]}"; do
    if ! dpkg -s "$dep" &>/dev/null; then
      MISSING_DEPS+=("$dep")
    fi
  done

  if (( ${#MISSING_DEPS[@]} > 0 )); then
    info "  Installing Chromium deps: ${MISSING_DEPS[*]}"
    if ! apt_install "${MISSING_DEPS[@]}" 2>/dev/null; then
      # If the first set failed, try the other naming variant
      warn "  Retrying with alternate package names..."
      ALT_DEPS=()
      for dep in "${MISSING_DEPS[@]}"; do
        # Toggle t64 suffix
        if [[ "$dep" == *t64 ]]; then
          ALT_DEPS+=("${dep%t64}")
        else
          ALT_DEPS+=("${dep}t64")
        fi
      done
      apt_install "${ALT_DEPS[@]}" 2>/dev/null || warn "  Some Chromium deps could not be installed"
    fi
  fi
  ok "Chromium dependencies ready"
fi

# ── 9. Wordlists & Templates ────────────────────────────────
info "Setting up wordlists & templates directory..."
mkdir -p "$WORDLISTS_DIR" "$TEMPLATES_DIR"

# SecLists
if [[ -d "$WORDLISTS_DIR/SecLists/Discovery" ]]; then
  ok "  SecLists already installed"
else
  info "  Cloning SecLists (shallow)..."
  git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$WORDLISTS_DIR/SecLists" 2>/dev/null \
    || warn "  SecLists clone failed — install later via the app UI"
fi

# Nuclei Templates
if [[ -d "$TEMPLATES_DIR/nuclei-templates/http" ]]; then
  ok "  Nuclei Templates already installed"
else
  if need nuclei; then
    info "  Updating Nuclei templates..."
    nuclei -update-templates -td "$TEMPLATES_DIR/nuclei-templates" 2>/dev/null \
      || git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git "$TEMPLATES_DIR/nuclei-templates" 2>/dev/null \
      || warn "  Nuclei templates install failed — install later via the app UI"
  else
    info "  Cloning Nuclei templates..."
    git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git "$TEMPLATES_DIR/nuclei-templates" 2>/dev/null \
      || warn "  Nuclei templates clone failed"
  fi
fi

# Fuzzing Templates
if [[ -d "$TEMPLATES_DIR/fuzzing-templates" ]]; then
  ok "  Fuzzing Templates already installed"
else
  info "  Cloning Fuzzing Templates..."
  git clone --depth 1 https://github.com/projectdiscovery/fuzzing-templates.git "$TEMPLATES_DIR/fuzzing-templates" 2>/dev/null \
    || warn "  Fuzzing templates clone failed"
fi

# PayloadsAllTheThings
if [[ -d "$WORDLISTS_DIR/PayloadsAllTheThings" ]]; then
  ok "  PayloadsAllTheThings already installed"
else
  info "  Cloning PayloadsAllTheThings..."
  git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git "$WORDLISTS_DIR/PayloadsAllTheThings" 2>/dev/null \
    || warn "  PayloadsAllTheThings clone failed"
fi

# ── 10. npm install ──────────────────────────────────────────
info "Installing Node.js dependencies..."
cd "$SCRIPT_DIR"

# Re-source nvm and activate the correct version
if [[ -s "$NVM_DIR/nvm.sh" ]]; then
  source "$NVM_DIR/nvm.sh"
fi
nvm use "$NODE_MAJOR" 2>/dev/null || true

# Clean install if node_modules looks broken
if [[ -d node_modules ]] && ! node -e "require('express')" 2>/dev/null; then
  warn "node_modules looks corrupted — doing a clean install"
  rm -rf node_modules package-lock.json
fi

if npm install; then
  ok "Node.js dependencies installed"
else
  fail "npm install failed!"
  fail "Troubleshooting:"
  fail "  1. Make sure you're on Node $(node -v) (need v${NODE_MAJOR}.x)"
  fail "  2. Try: rm -rf node_modules package-lock.json && npm install"
  fail "  3. On Kali/WSL, ensure build-essential is installed: sudo apt install build-essential"
  ((ERRORS++))
fi

# ── 11. .env file ────────────────────────────────────────────
if [[ ! -f "$SCRIPT_DIR/.env" ]]; then
  if [[ -f "$SCRIPT_DIR/.env.example" ]]; then
    info "Creating .env from .env.example..."
    cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
    ok ".env created — edit it if needed"
  else
    warn ".env.example not found — skipping .env creation"
  fi
else
  ok ".env already exists"
fi

# ── 12. Build check ─────────────────────────────────────────
info "Running lint check..."
npm run lint 2>/dev/null && ok "Lint passed" || { warn "Lint check had issues"; ((ERRORS++)); }

info "Running build..."
npm run build 2>/dev/null && ok "Build passed" || { warn "Build had issues"; ((ERRORS++)); }

# ── Summary ──────────────────────────────────────────────────
echo ""
if (( ERRORS == 0 )); then
  echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}║              Setup Complete!                      ║${NC}"
  echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
else
  echo -e "${YELLOW}╔══════════════════════════════════════════════════╗${NC}"
  echo -e "${YELLOW}║        Setup Complete (with $ERRORS warning(s))       ║${NC}"
  echo -e "${YELLOW}╚══════════════════════════════════════════════════╝${NC}"
fi
echo ""
echo -e "  ${CYAN}Wordlists:${NC}  $WORDLISTS_DIR"
echo -e "  ${CYAN}Templates:${NC}  $TEMPLATES_DIR"
echo -e "  ${CYAN}Node.js:${NC}    $(node -v 2>/dev/null || echo 'not found')"
echo -e "  ${CYAN}npm:${NC}        $(npm -v 2>/dev/null || echo 'not found')"
echo ""
echo -e "  ${YELLOW}To start:${NC}"
if need ollama; then
  echo -e "    1. Start Ollama:  ${GREEN}ollama serve${NC}"
else
  echo -e "    1. (Optional) Install Ollama: ${GREEN}https://ollama.com/download${NC}"
fi
echo -e "    2. Run the app:   ${GREEN}npm run dev${NC}"
echo -e "    3. Open browser:  ${GREEN}http://localhost:3000${NC}"
echo ""

if $IS_WSL; then
  echo -e "  ${CYAN}WSL Tips:${NC}"
  echo -e "    - If 'nvm' is not found in new terminals, run: ${GREEN}source ~/.bashrc${NC} or ${GREEN}source ~/.zshrc${NC}"
  echo -e "    - Ollama may need to run as: ${GREEN}ollama serve &${NC} (no systemd)"
  echo ""
fi

echo -e "  ${YELLOW}Installed tools:${NC}"

TOOL_LIST=(nmap subfinder amass httpx nuclei ffuf katana sqlmap gau gobuster dalfox nikto pdtm naabu dnsx tlsx interactsh-client whatweb dirb uncover)
INSTALLED=0; MISSING_TOOLS=()
for t in "${TOOL_LIST[@]}"; do
  if need "$t"; then
    ((INSTALLED++))
  else
    MISSING_TOOLS+=("$t")
  fi
done
echo -e "    ${GREEN}$INSTALLED/${#TOOL_LIST[@]}${NC} tools installed"
if (( ${#MISSING_TOOLS[@]} > 0 )); then
  echo -e "    ${YELLOW}Missing:${NC} ${MISSING_TOOLS[*]}"
  echo -e "    ${YELLOW}Install missing tools from the Security Arsenal tab in the app${NC}"
fi
echo ""
