echo "##### System update #####"
sudo apt-get update && sudo apt-get upgrade -y

echo "##### Tools installation #####"
sudo apt-get install -y dnsutils python3-pip chromium-browser=1:85.0.4183.83-0ubuntu2.22.04.1 chromium-chromedriver=1:85.0.4183.83-0ubuntu2.22.04.1 libnss3 cron

echo "##### env file #####"
mv env .env

echo "##### Installing python dependencies #####"
sudo pip3 install -r /home/$USER/urlmalguard/requirements.txt

echo "##### Creation of the UrlMalGuard service #####"
cat <<EOL | sudo tee /etc/systemd/system/urlmalguard.service > /dev/null
[Unit]
Description=UrlMalGuard Service
After=network.target

[Service]
ExecStart=/usr/local/bin/gunicorn -w 4 -b 0.0.0.0:8000 urlmalguard_api:app
WorkingDirectory=/home/$USER/urlmalguard
Restart=on-failure
User=$USER
Group=$USER
Environment=PATH=/usr/bin:/usr/local/bin
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOL

echo "##### Reload daemon #####"
sudo systemctl daemon-reload

echo "##### Enable service #####"
sudo systemctl enable urlmalguard.service

echo "##### Start UrlMalGuard #####"
sudo systemctl start urlmalguard.service

echo "##### Setting up cron job to delete files in /urlmalguard/static/snapshots #####"
(sudo crontab -l 2>/dev/null; echo "0 0,12 * * * rm -rf /urlmalguard/static/snapshots/*") | sudo crontab -