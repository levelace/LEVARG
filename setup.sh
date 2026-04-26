#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# LevarG — One-Shot Setup Runner
# Installs every dependency/prerequisite and prepares the app.
# Usage:  chmod +x setup.sh && ./setup.sh
# ──────────────────────────────────────────────────────────────
set -euo pipefail

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

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║       LevarG — Full Environment Setup            ║${NC}"
echo -e "${GREEN}║       LEVELACE SENTINEL LLC                      ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# ── Detect OS ────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"
info "Detected: $OS / $ARCH"

is_linux()  { [[ "$OS" == "Linux" ]]; }
is_mac()    { [[ "$OS" == "Darwin" ]]; }

if ! is_linux && ! is_mac; then
  fail "This script supports Linux and macOS. For Windows, use WSL2."
  exit 1
fi

# ── Package manager helpers ──────────────────────────────────
apt_install() {
  sudo apt-get update -qq
  sudo apt-get install -y "$@"
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
    apt_install "${PKGS[@]}"
  fi
elif is_mac; then
  if ! need brew; then
    info "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
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

if [[ ! -d "$NVM_DIR" ]]; then
  info "Installing nvm..."
  curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
fi

# Source nvm (works even if .bashrc hasn't been reloaded)
[[ -s "$NVM_DIR/nvm.sh" ]] && source "$NVM_DIR/nvm.sh"

if ! need nvm; then
  fail "nvm installation failed. Please install Node.js $NODE_MAJOR manually."
  exit 1
fi

CURRENT_NODE="$(node -v 2>/dev/null || echo 'none')"
if [[ "$CURRENT_NODE" != v${NODE_MAJOR}.* ]]; then
  info "Installing Node.js $NODE_MAJOR..."
  nvm install "$NODE_MAJOR"
  nvm use "$NODE_MAJOR"
else
  ok "Node.js $CURRENT_NODE already installed"
fi
nvm alias default "$NODE_MAJOR" 2>/dev/null || true

# ── 3. Go (for ProjectDiscovery tools / pdtm) ───────────────
info "Checking Go..."
if ! need go; then
  GO_VERSION="1.23.9"
  case "$ARCH" in
    x86_64|amd64) GO_ARCH="amd64" ;;
    aarch64|arm64) GO_ARCH="arm64" ;;
    *) fail "Unsupported arch for Go: $ARCH"; exit 1 ;;
  esac
  if is_linux; then GO_OS="linux"; else GO_OS="darwin"; fi
  GO_TAR="go${GO_VERSION}.${GO_OS}-${GO_ARCH}.tar.gz"
  info "Installing Go $GO_VERSION..."
  curl -fsSL "https://go.dev/dl/$GO_TAR" -o "/tmp/$GO_TAR"
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf "/tmp/$GO_TAR"
  rm -f "/tmp/$GO_TAR"
  export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
  ok "Go $(go version | awk '{print $3}') installed"
else
  export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
  ok "Go $(go version | awk '{print $3}') already installed"
fi

# Ensure GOPATH/bin is in PATH for this session and future shells
if ! echo "$PATH" | grep -q "$HOME/go/bin"; then
  export PATH="$HOME/go/bin:$PATH"
fi
grep -q 'go/bin' "$HOME/.bashrc" 2>/dev/null || echo 'export PATH="$HOME/go/bin:/usr/local/go/bin:$PATH"' >> "$HOME/.bashrc"

# ── 4. Ollama (local AI — free, no API key) ──────────────────
info "Checking Ollama..."
if ! need ollama; then
  info "Installing Ollama..."
  curl -fsSL https://ollama.com/install.sh | sh
  ok "Ollama installed"
else
  ok "Ollama already installed"
fi

# Pull default model if not present
if ollama list 2>/dev/null | grep -q "llama3.2"; then
  ok "Model llama3.2 already pulled"
else
  info "Pulling llama3.2 model (~2 GB)..."
  ollama pull llama3.2 || warn "Could not pull model — you can run 'ollama pull llama3.2' later"
fi

# ── 5. pdtm (ProjectDiscovery Tool Manager) ──────────────────
info "Checking pdtm..."
if ! need pdtm; then
  info "Installing pdtm..."
  go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest 2>/dev/null \
    || {
      # Fallback: download binary
      case "${OS}_${ARCH}" in
        Linux_x86_64|Linux_amd64)   PDTM_BIN="pdtm_linux_amd64.zip" ;;
        Linux_aarch64|Linux_arm64)  PDTM_BIN="pdtm_linux_arm64.zip" ;;
        Darwin_x86_64|Darwin_amd64) PDTM_BIN="pdtm_macOS_amd64.zip" ;;
        Darwin_arm64)               PDTM_BIN="pdtm_macOS_arm64.zip" ;;
        *) fail "No pdtm binary for $OS/$ARCH"; PDTM_BIN="" ;;
      esac
      if [[ -n "$PDTM_BIN" ]]; then
        curl -fsSL "https://github.com/projectdiscovery/pdtm/releases/latest/download/$PDTM_BIN" -o /tmp/pdtm.zip
        sudo unzip -o /tmp/pdtm.zip -d /usr/local/bin && rm -f /tmp/pdtm.zip
      fi
    }
  if need pdtm; then ok "pdtm installed"; else warn "pdtm install failed — install manually"; fi
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
    apt_install "$apt_pkg" 2>/dev/null || warn "  apt install $apt_pkg failed"
  elif is_mac; then
    brew_install "$brew_pkg" 2>/dev/null || warn "  brew install $brew_pkg failed"
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
for gotool in "github.com/lc/gau/v2/cmd/gau@latest" "github.com/hahwul/dalfox/v2@latest" "github.com/OJ/gobuster/v3@latest"; do
  TOOL_BIN="$(basename "${gotool%%@*}")"
  if ! need "$TOOL_BIN"; then
    info "  Installing $TOOL_BIN via go install..."
    go install -v "$gotool" 2>/dev/null || warn "  go install $TOOL_BIN failed"
  else
    ok "  $TOOL_BIN already installed"
  fi
done

# ── 8. Chromium for Puppeteer ────────────────────────────────
info "Checking Chromium for Puppeteer..."
if is_linux; then
  CHROME_DEPS=(libnss3 libatk1.0-0t64 libatk-bridge2.0-0t64 libcups2t64 libxdamage1 libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libasound2t64 libxshmfence1)
  MISSING_DEPS=()
  for dep in "${CHROME_DEPS[@]}"; do
    if ! dpkg -s "$dep" &>/dev/null; then
      # Try without the t64 suffix (older distros)
      ALT="${dep%t64}"
      if [[ "$ALT" != "$dep" ]] && dpkg -s "$ALT" &>/dev/null; then continue; fi
      MISSING_DEPS+=("$dep")
    fi
  done
  if (( ${#MISSING_DEPS[@]} > 0 )); then
    info "  Installing Chromium deps: ${MISSING_DEPS[*]}"
    sudo apt-get install -y "${MISSING_DEPS[@]}" 2>/dev/null || sudo apt-get install -y "${MISSING_DEPS[@]/%t64/}" 2>/dev/null || true
  fi
fi
ok "Chromium dependencies ready"

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

# Ensure we're on the right Node version
[[ -s "$NVM_DIR/nvm.sh" ]] && source "$NVM_DIR/nvm.sh"
nvm use "$NODE_MAJOR" 2>/dev/null || true

npm install
ok "Node.js dependencies installed"

# ── 11. .env file ────────────────────────────────────────────
if [[ ! -f "$SCRIPT_DIR/.env" ]]; then
  info "Creating .env from .env.example..."
  cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
  ok ".env created — edit it if needed"
else
  ok ".env already exists"
fi

# ── 12. Build check ─────────────────────────────────────────
info "Running lint check..."
npm run lint 2>/dev/null && ok "Lint passed" || warn "Lint check had issues"

info "Running build..."
npm run build 2>/dev/null && ok "Build passed" || warn "Build had issues"

# ── Summary ──────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              Setup Complete!                      ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}Wordlists:${NC}  $WORDLISTS_DIR"
echo -e "  ${CYAN}Templates:${NC}  $TEMPLATES_DIR"
echo ""
echo -e "  ${YELLOW}To start:${NC}"
echo -e "    1. Start Ollama:  ${GREEN}ollama serve${NC}"
echo -e "    2. Run the app:   ${GREEN}npm run dev${NC}"
echo -e "    3. Open browser:  ${GREEN}http://localhost:3000${NC}"
echo ""
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
