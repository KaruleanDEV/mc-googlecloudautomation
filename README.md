Automated "Wake-on-LAN" for Minecraft servers hosted on Google Cloud Platform (GCP). This script acts as a lightweight proxy that monitors player activity, manages DNS records via Cloudflare, and powers VMs up or down. 


1. Prerequisites
Ensure you have the following installed on your Gateway machine (the one that stays 24/7):
Usually a free-tier micro instance

-Python 3.8+
-GCP Service Account Key (with Compute Instance Admin permissions)
-Cloudflare API Token (with DNS Edit permissions)

2. Clone & Install Dependencies
git clone https://github.com/KaruleanDEV/mc-googlecloudautomation.git
cd mc-gateway-orchestrator
pip install python-dotenv google-cloud-compute requests

3. Create a .env file in the root directory (follow example)

4. Deploy as systemd service (Optional)
```bash
cat <<EOF | sudo tee /etc/systemd/system/gateway.service
[Unit]
Description=Gateway Minecraft Orchestrator
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$(pwd)
ExecStart=$(which python3) $(pwd)/gateway.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1
Environment=TERM=xterm-256color
Environment=PYTHONIOENCODING=utf-8
StandardOutput=inherit
StandardError=inherit

[Install]
WantedBy=multi-user.target
EOF
```

sudo systemctl daemon-reload
sudo systemctl enable gateway
sudo systemctl start gateway

5. Read Logs
journalctl -u gateway.service -f -o cat
