# MISP

```sh
$ git clone https://github.com/MISP/misp-docker.git
$ sudo docker-compose up

$ git clone https://github.com/MISP/MISP-Taxii-Server.git
```

```sh
sudo service apache2 restart
sudo service redis-server restart
sudo -u www-data /var/www/MISP/app/Console/worker/start.sh
```

