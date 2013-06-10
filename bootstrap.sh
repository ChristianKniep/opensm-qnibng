#!/usr/bin/env bash

if [ -f /vagrant/proxy.sh ]; then
    source /vagrant/proxy.sh
    fi

if [ ! -f /etc/yum.repos.d/epel.repo ];then
    cd /tmp
    wget  http://download.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm
    rpm -i epel-release-6-8.noarch.rpm
fi
# update yum
yum update -y 

#
yum install -y git-core automake autoconf make bison flex file vim \
               libtool screen python-devel ibsim infiniband-diags \
	       libibumad-devel libibmad-devel

# compiling opensm-qnibng
cd /vagrant
sh autogen.sh && ./configure --enable-default-event-plugin
make && make install

# install graphite requirements
yum install -y django-tagging python-devel python-pip python-zope-interface \
               pycairo python-twisted gcc make nc bitmap-fonts-compat \
	       mod_wsgi httpd
# install graphite via pip
python-pip install whisper carbon graphite-web


### config & run
chkconfig iptables off
service iptables stop
cp /opt/graphite/conf/carbon.conf.example /opt/graphite/conf/carbon.conf

cat << EOF >  /opt/graphite/conf/storage-schemas.conf
[carbon]
pattern = ^carbon\.
retentions = 60:90d

[ib]
pattern = ^ib\.
retentions = 5s:1d

[default_1min_for_1day]
pattern = .*
retentions = 60s:1d
EOF
/opt/graphite/bin/carbon-cache.py start



cat << EOF >  /opt/graphite/webapp/graphite/local_settings.py
DATABASES = {
    'default': {
        'NAME': '/opt/graphite/storage/graphite.db',
        'ENGINE': 'django.db.backends.sqlite3',
        'USER': '',
        'PASSWORD': '',
        'HOST': '',
        'PORT': ''
    }
}
DEBUG = False
import logging
if DEBUG:
    # will output to your console
    logging.basicConfig(
        level = logging.DEBUG,
        format = '%(asctime)s %(levelname)s %(message)s',
    )
else:
    # will output to logging file
    logging.basicConfig(
        level = logging.DEBUG,
        format = '%(asctime)s %(levelname)s %(message)s',
        filename = '/opt/graphite/log/graphite-web.log',
        filemode = 'a'
    )
EOF
mkdir /opt/graphite/log
chown apache:apache -R /opt/graphite/storage/
chown apache:apache -R /opt/graphite/log
cd /vagrant
python /opt/graphite/webapp/graphite/manage.py syncdb --noinput

chkconfig httpd on
chown apache:apache -R /opt/graphite/storage/
cp /opt/graphite/conf/graphite.wsgi.example /opt/graphite/conf/graphite.wsgi
cp /opt/graphite/examples/example-graphite-vhost.conf /etc/httpd/conf.d/graphite-vhost.conf
sed -i -e 's#@DJANGO_ROOT@#/usr/lib/python2.6/site-packages/django#' /etc/httpd/conf.d/graphite-vhost.conf
service httpd start

cat << EOF > 4nodes.nlst
Switch  4 "switch1"
[1]     "node1"[1]
[2]     "node2"[1]
[3]     "node3"[1]
[4]     "node4"[1]

Hca     1 "node1"
[1]     "switch1"[1]

Hca     1 "node2"
[1]     "switch1"[2]

Hca     1 "node3"
[1]     "switch1"[3]

Hca     1 "node4"
[1]     "switch1"[4]
EOF
# new screen
ibsim -s 4nodes.nlst > /var/log/ibsim.out 2> /var/log/ibsim.err &


export LD_PRELOAD=/usr/lib64/umad2sim/libumad2sim.so
export SIM_HOST=node1
opensm -F /vagrant/opensm.conf
