**Django common commands**

```python
django-admin startproject mysite

```

**password reset**

```python
from django.contrib.auth.models import User
u = User.objects.get(username__exact='admin')
u.set_password('password')
u.save()
```



## Issues

Import_Export + Jet library with django.jquery

```javascript
site-packages\import_export\templates\admin\import_export\base.html

<script type="text/javascript" src="{% static "admin/js/vendor/jquery/jquery.js" %}"></script>
<script type="text/javascript" src="{% static "admin/js/jquery.init.js" %}"></script>
```

Django Jet `django.gettext`

```javascript
site-packages\jet\templates\admin\base.html
    <script>
    django.gettext = window.gettext
    </script>
```

Deploying with Apache + mod_wsgi

```shell
sudo apt-get update
sudo apt-get install python3-pip apache2 libapache2-mod-wsgi-py3

python3 manage.py collectstatic
```

**configure apache**

sudo nano /etc/apache2/sites-available/000-default.conf

```shell
<VirtualHost *:80>
        # The ServerName directive sets the request scheme, hostname and port that
        # the server uses to identify itself. This is used when creating
        # redirection URLs. In the context of virtual hosts, the ServerName
        # specifies what hostname must appear in the request's Host: header to
        # match this virtual host. For the default virtual host (this file) this
        # value is not decisive as it is used as a last resort host regardless.
        # However, you must set it for any further virtual host explicitly.
        #ServerName www.example.com

ServerAdmin naser.khanafeer@gmail.com
ServerName name.com
ServerAlias www.name.com
Alias /favicon.ico /usr/local/site_name/static/img/logo/logo.ico

Alias /media/ /usr/local/site_name/media/
Alias /static/ /usr/local/site_name/static/
Alias /uploads /usr/local/site_name/static/uploads/


<Directory /usr/local/site_name/static>
Require all granted
</Directory>

<Directory /usr/local/site_name/media>
Require all granted
</Directory>

<Directory /usr/local/site_name/static/uploads>
Require all granted
</Directory>


WSGIScriptAlias / /usr/local/site_name/site_name/wsgi.py
WSGIDaemonProcess site_name python-path=/usr/local/site_name python-home=/usr/local/site_name/site_namevenv
WSGIProcessGroup site_name

<Directory /usr/local/site_name/site_name>
        <Files wsgi.py>
                Require all granted
        </Files>
</Directory>


ErrorLog ${APACHE_LOG_DIR}/error.log
CustomLog ${APACHE_LOG_DIR}/access.log combined

        # For most configuration files from conf-available/, which are
        # enabled or disabled at a global level, it is possible to
        # include a line for only one particular virtual host. For example the
        # following line enables the CGI configuration for this host only
        # after it has been globally disabled with "a2disconf".
        #Include conf-available/serve-cgi-bin.conf
RewriteEngine on
RewriteCond %{SERVER_NAME} =www.name.com [OR]
RewriteCond %{SERVER_NAME} =name.com
RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</VirtualHost>
```

**Configure Let's encrypt**

```shell
sudo apt install certbot python3-certbot-apache
certbot --apache -d *.name.com -d www.name.com
sudo apt install python-certbot-apache
```

```sh
sudo certbot delete --cert-name 
```

https://docs.djangoproject.com/en/3.2/howto/deployment/wsgi/modwsgi/

**Useful commands**

```shell
./python3 -m pip install django-ckeditor
```

**Multi Tenancy**

```shell
./manage.py migrate_schemas
python manage.py migrate_schemas --executor=parallel

/manage.py tenant_command createsuperuser --username=admin --schema=main


Super User
./manage.py createsuperuser --username=admin --schema=customer1


list_tenants
for t in $(./manage.py list_tenants | cut -f1);
do
    ./manage.py tenant_command dumpdata --schema=$t --indent=2 auth.user > ${t}_users.json;
done


tenant = Client(domain_url="www.name.com",
                schema_name='name',
                name='name Inc.')
tenant.save()
```
