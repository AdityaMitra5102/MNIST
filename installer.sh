sudo apt update
sudo apt install -y git python3 python3-dev python3-pip python3-flask python3-pyrad apache2 libapache2-mod-wsgi-py3 avahi-daemon avahi-utils

git clone https://github.com/AdityaMitra5102/MNIST

sudo chmod -R 777 MNIST
sudo chmod -R 777 MNIST/templates

sudo ln -sT $(pwd)/MNIST /var/www/html/flaskapp
sudo cp -f 000-default.conf /var/etc/apache2/sites-enabled
sudo cp -f myrad.py /usr/bin
sudo cp -f myMAuthN.py /usr/bin
sudo chmod 777 /usr/bin/myrad.py
sudo chmod 777 /usr/bin/pyMAuthN.py

sudo hostnamectl set-hostname mnist

sudo cp myrad.service /etc/systemd/system
sudo systemctl daemon-reload

sudo cp -r rad /etc
sudo chmod 777 /etc/rad

sudo systemctl restart avahi-daemon
sudo systemctl enable avahi-daemon
sudo systemctl enable myrad.service
sudo systemctl restart myrad.service