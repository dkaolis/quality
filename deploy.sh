#!/bin/bash
# eQuality Deployment Script — Ubuntu 22.04 LTS (first-time setup)
# Χρήση: sudo bash deploy.sh

set -e

APP_NAME="quality"
APP_DIR="/opt/${APP_NAME}"
APP_USER="quality"
LOG_DIR="/var/log/${APP_NAME}"
VENV_DIR="${APP_DIR}/venv"
PORT=5002

echo "=== eQuality Deployment ==="
echo "Εγκατάσταση: ${APP_DIR}"

# 1. System dependencies
echo "[1/7] System dependencies..."
apt-get update -qq
apt-get install -y python3 python3-pip python3-venv nginx

# 2. Δημιουργία χρήστη συστήματος
echo "[2/7] System user..."
id -u ${APP_USER} &>/dev/null || useradd -r -s /bin/false ${APP_USER}

# 3. Αντιγραφή αρχείων
echo "[3/7] Application files..."
mkdir -p ${APP_DIR} ${LOG_DIR} ${APP_DIR}/uploads ${APP_DIR}/reports
cp -r . ${APP_DIR}/
chown -R ${APP_USER}:${APP_USER} ${APP_DIR} ${LOG_DIR}

# 4. Python venv
echo "[4/7] Python virtual environment..."
python3 -m venv ${VENV_DIR}
${VENV_DIR}/bin/pip install --upgrade pip
${VENV_DIR}/bin/pip install -r ${APP_DIR}/requirements.txt

# 5. MySQL (προαιρετικό — χωρίς settings.json τρέχει με SQLite)
echo "[5/7] MySQL: ρύθμισε χειροκίνητα το settings.json αν θες MySQL (κενό db_host = SQLite)."

# 6. Systemd service
echo "[6/7] Systemd service..."
cat > /etc/systemd/system/${APP_NAME}.service << EOF
[Unit]
Description=eQuality - Quality Assurance Platform (OKYpY)
After=network.target mysql.service

[Service]
Type=simple
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_DIR}
Environment="PATH=${VENV_DIR}/bin"
ExecStart=${VENV_DIR}/bin/gunicorn --workers 4 --bind 0.0.0.0:${PORT} --timeout 120 --access-logfile ${LOG_DIR}/access.log --error-logfile ${LOG_DIR}/error.log app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ${APP_NAME}
systemctl restart ${APP_NAME}

# 7. Nginx reverse proxy (vhost για quality.shso.online — το cloudflared δείχνει εδώ)
echo "[7/7] Nginx configuration..."
cat > /etc/nginx/sites-available/${APP_NAME} << 'EOF'
server {
    listen 80;
    server_name quality.shso.online;

    client_max_body_size 50M;

    location / {
        proxy_pass http://127.0.0.1:5002;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120;
    }

    location /static/ {
        alias /opt/quality/static/;
        expires 1d;
    }
}
EOF

ln -sf /etc/nginx/sites-available/${APP_NAME} /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx

echo ""
echo "=== Deployment Complete ==="
echo "Local:  http://127.0.0.1:${PORT}"
echo "Domain: http://quality.shso.online (μέσω cloudflared → αυτόν τον server)"
echo "Default login: admin / admin123 — ΑΛΛΑΞΕ ΤΟΝ ΚΩΔΙΚΟ ΑΜΕΣΩΣ"
