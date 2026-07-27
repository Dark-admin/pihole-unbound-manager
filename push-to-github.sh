#!/usr/bin/env bash
#
# push-to-github.sh — Sube el proyecto pihole-unbound-manager a GitHub
# Autor: nexo (Dᵃʳᵏ- ᵃᵈᵐᶤᶰ)
#
# IMPORTANTE DE SEGURIDAD:
#   El token (si se pasa) SOLO se usa en el comando `git push` inline.
#   NUNCA se guarda en el remote (para no dejarlo en texto plano en .git/config).
#   El remote se configura SIEMPRE sin token.
#
# Uso:
#   ./push-to-github.sh <usuario-github> <nombre-repo> [token-opcional]
#
set -euo pipefail

USER="${1:-}"
REPO="${2:-pihole-unbound-manager}"
TOKEN="${3:-}"
DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ -z "$USER" ]]; then
  read -rp "Usuario de GitHub: " USER
fi

cd "$DIR"

# Configurar identidad local (solo para este repo)
git config user.email "nexo@local" 2>/dev/null || true
git config user.name "$USER" 2>/dev/null || true

# .gitignore
cat > .gitignore <<'EOF'
*.log
__pycache__/
.DS_Store
EOF

# Commit inicial si hay cambios
git add -A
git commit -q -m "Pi-hole + Unbound Manager: installer, TUI, dashboard web, GitHub push" 2>/dev/null || echo "Sin cambios que commitear"

# Remote SIEMPRE sin token (limpio)
REMOTE_CLEAN="https://github.com/$USER/$REPO.git"
git remote remove origin 2>/dev/null || true
git remote add origin "$REMOTE_CLEAN"

echo "==> Conectando a $REMOTE_CLEAN"

# Si hay token, usarlo SOLO en el push inline (no se persiste en .git/config)
if [[ -n "$TOKEN" ]]; then
  PUSH_URL="https://$USER:$TOKEN@github.com/$USER/$REPO.git"
else
  PUSH_URL="$REMOTE_CLEAN"
fi

echo "==> Subiendo a GitHub..."
if git push "$PUSH_URL" -u origin main 2>/dev/null; then
  echo "✓ Subido a main"
elif git push "$PUSH_URL" -u origin master 2>/dev/null; then
  echo "✓ Subido a master"
else
  echo "✗ Push falló. Verifica credenciales o crea el repo en GitHub primero."
  echo "  URL: https://github.com/new"
  exit 1
fi

echo "✓ Listo: https://github.com/$USER/$REPO"
echo "  (El token no quedó guardado en la configuración local)"
