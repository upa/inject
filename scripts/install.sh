


install -o root -g root -m 644 ../inject.ini /etc/
install -o root -g root -m 755 -d /var/local/inject
install -o root -g root -m 644  ../inject.py /var/local/inject/
install -o root -g root -m 755 ../injectl /usr/local/bin/
install -o root -g root -m 755 inject-start-stop.sh /usr/local/bin/
