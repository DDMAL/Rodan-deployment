"""
Rodan Deployment Tool

Copyright 2011-2016 Distributed Digital Music Archives and Libraries Lab
"""
__version__ = '1.0.0'

RODAN_COMPONENTS = ('rodan_task_queue', 'rodan_database', 'rodan_resource_file_server', 'rodan_worker', 'rodan_web_server')

import argparse
import os, stat
import socket
import json
import random, string

import re
def is_valid_hostname(hostname):
    if len(hostname) > 255-5:  # reserve few characters...
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

def MSG_ERROR(msg):
    FAIL = '\033[91m'  # color code for red
    ENDC = '\033[0m'   # color code end
    print "{0}{1}{2}".format(FAIL, msg, ENDC)
    exit(1)

def MSG_NOTICE(msg):
    print msg

def main():
    parser = argparse.ArgumentParser(description='''
Generate bash scripts that install Rodan on distributed machines with a Vagrantfile for testing in multiple VMs.

Examples:
 TODO
''')
    parser.add_argument('--output-folder', required=True, type=str, help="output folder")
    parser.add_argument('MACHINE_CONFIGURATION', nargs='+', type=str, help="a '+' separated combination of Rodan components that include: 'rodan_task_queue', 'rodan_database', 'rodan_resource_file_server', 'rodan_worker', and 'rodan_web_server'.\nRestriction: 'rodan_worker' should appear at least once but other components should exactly appear once.\nExample: \nrodan_database+rodan_resource_file_server rodan_task_queue+rodan_worker rodan_worker rodan_web_server+rodan_worker")
    parser.add_argument('--os', required=True, type=str, choices=('ubuntu:14.04', ), help="base operating system name:version (for now, only supports ubuntu 14.04)")

    #parser.add_argument('--amqp-port', default=5672, type=int, choices=(5672, ), help="Rodan task queue port")  # may be able to extend it in future
    parser.add_argument('--amqp-vhost', type=str, default='rodan', help="Rodan task queue vhost name (default rodan)")
    parser.add_argument('--amqp-user', type=str, default='rodan', help="Rodan task queue user name (default rodan)")
    parser.add_argument('--amqp-password', type=str, default='rodan', help="Rodan task queue user password (default rodan)")

    #parser.add_argument('--db-port', default=5432, type=int, choices=(5432, ), help="Rodan database port")  # may be able to extend it in future
    parser.add_argument('--db-name', type=str, default='rodan', help="Rodan database name (default rodan)")
    parser.add_argument('--db-user', type=str, default='rodan', help="Rodan database user name (default rodan)")
    parser.add_argument('--db-password', required=True, type=str, help="Rodan database user password")
    parser.add_argument('--db-su-user', type=str, default='rodan_superuser', help="Rodan database superuser name (default rodan_superuser)")
    parser.add_argument('--db-su-password', required=True, type=str, help="Rodan database superuser password")

    parser.add_argument('--nfs-server-directory', required=True, type=str, help="the local directory shared by Rodan resource file server")

    parser.add_argument('--server-domain-name', required=True, type=str, help="Rodan server domain name (also as the hostname suffix of machines)")
    parser.add_argument('--server-paginate-by', required=True, type=int, help="Rodan server PAGINATE_BY setting (the number of objects on a page)")
    parser.add_argument('--server-client-max-body-size', required=True, type=str, help="the maximum size of HTTP request that Rodan server will allow (e.g., 20M, 2G, or etc.). It should be related to the size of resource file.")
    parser.add_argument('--server-ssl-cert-path', required=True, type=str, help="Rodan server SSL certification path")
    parser.add_argument('--server-ssl-cert-key-path', required=True, type=str, help="Rodan server SSL certification key path")

    parser.add_argument('--rodan-app-directory', required=True, type=str, help="the directory on Rodan workers and web server that will contain Rodan code")
    parser.add_argument('--rodan-data-mount-point', required=True, type=str, help="where other Rodan workers and Rodan server mount the resource files")
    parser.add_argument('--package-src-directory', required=True, type=str, help="the directory on Rodan workers and web server that will contain the source codes of packages that Rodan require")
    parser.add_argument('--rodan-admin-user', required=True, type=str, help="Rodan admin user name")
    parser.add_argument('--rodan-admin-password', required=True, type=str, help="Rodan admin user password")

    parser.add_argument('--debug', action='store_true', help="enable debug mode on Rodan server (not workers)")
    parser.add_argument('--disable-diva', action='store_true', help="disable Diva.js image viewer")


    args = parser.parse_args()

    # check domain name
    if not is_valid_hostname(args.server_domain_name):
        MSG_ERROR("{0} is not a valid domain name.".format(args.server_domain_name))
    if args.server_domain_name[-1] == ".":
        args.server_domain_name = args.server_domain_name[:-1]

    # for all directories, add trailing slash
    args.rodan_app_directory = os.path.join(args.rodan_app_directory, '')
    args.rodan_data_mount_point = os.path.join(args.rodan_data_mount_point, '')
    args.package_src_directory = os.path.join(args.package_src_directory, '')

    # machine configuration
    mcs = getattr(args, 'MACHINE_CONFIGURATION')

    ## cleaned list that contains the configuration of every machine
    components_cleaned = []
    ips_cleaned = []

    ## record which component is on which machine #.
    components_distribution = {}
    for c in RODAN_COMPONENTS:
        components_distribution[c] = []

    ## Parse machine configuration
    for i, mc in enumerate(mcs):
        ## check if 'mc' is formatted as xxxx+xxxx+....+xxxx@ip_address
        if '@' not in mc:
            MSG_ERROR("Improperly formatted machine configuration #{0}: {1}".format(i+1, mc))
        components_str, ip_address = mc.split('@', 1)

        ## check validity of ip address
        try:
            socket.inet_aton(ip_address) # IPv4
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, ip_address)  # IPv6
            except socket.error:
                MSG_ERROR("Invalid IP address in machine configuration #{0}: {1}".format(i+1, ip_address))

        ## check duplicate ip addresses
        if ip_address in ips_cleaned:
            MSG_ERROR("Duplicate IP address '{0}' in machine configuration".format(ip_address))

        ## check validity of components
        components = components_str.split('+')
        if len(components) != len(set(components)):
            MSG_ERROR("Duplicate components in machine configuration #{0}: {1}".format(i+1, components_str))
        for component in components:
            if component not in RODAN_COMPONENTS:
                MSG_ERROR("Invalid Rodan component in machine configuration #{0}: {1}".format(i+1, component))
            components_distribution[component].append(i)

        components_cleaned.append(components)
        ips_cleaned.append(ip_address)

    for c in RODAN_COMPONENTS:
        l = len(components_distribution[c])
        if c == 'rodan_worker':
            if l == 0:
                MSG_ERROR("{0} doesn't exist in provided machine configurations.".format(c))
        else:
            if l == 0:
                MSG_ERROR("{0} doesn't exist in provided machine configurations.".format(c))
            elif l > 1:
                MSG_ERROR("More than one {0} found in provided machine configurations.".format(c))

    # Check operating system
    os_name, os_version = args.os.split(":")
    MSG_NOTICE("Base operating system: {0}. Version: {1}".format(os_name, os_version))

    # Write files
    if os.path.exists(args.output_folder):
        MSG_ERROR("Folder '{0}' already exists. Please delete it or change another output folder.".format(args.output_folder))
    os.makedirs(args.output_folder)

    ## write configuration
    print str(args)
    with open(os.path.join(args.output_folder, "configuration.json"), 'w') as g:
        json.dump(args.__dict__, g, indent=4, sort_keys=True)


    ## generate shell commands (a list of list)
    shell_commands = []

    for i, components in enumerate(components_cleaned):
        cmds = []

        ## Check if source codes are provided
        if 'rodan_worker' in components or 'rodan_web_server' in components:
            # check Rodan source code
            cmds.append("""if test ! -d {0}Rodan; then
  echo "Please put Rodan source code under "{0}Rodan", and try again.";
  exit 1;
fi""".format(args.package_src_directory))

            cmds.append("""if test ! -f {0}Rodan/requirements.txt; then
  echo "Cannot find '{0}Rodan/requirements.txt'. Please check your Rodan source and try again."
  exit 1;
fi""".format(args.package_src_directory))

            if not args.disable_diva:
                # check kakadu 7.7
                cmds.append("""if test ! -f {0}v7_7-01273N.zip; then
  echo "Cannot find '{0}v7_7-01273N.zip'. Please copy your Kakadu source here and try again."
  exit 1;
fi""".format(args.package_src_directory))

        ## Check if SSL cert and key are provided (only server)
        if 'rodan_web_server' in components:
            cmds.append("""if test ! -f {0}; then
  echo "Please put Rodan server SSL certificate at '{0}', and try again.";
  exit 1;
fi""".format(args.server_ssl_cert_path))
            cmds.append("""if test ! -f {0}; then
  echo "Please put Rodan server SSL private key at '{0}', and try again.";
  exit 1;
fi""".format(args.server_ssl_cert_key_path))


        ## set hostname
        cmds.append('echo "m{0}.{1}" > /etc/hostname'.format(i+1, args.server_domain_name))  # permanent
        cmds.append('hostname `cat /etc/hostname`')  # temporary

        ## update system
        cmds.append('apt-get -y update && apt-get -y upgrade')

        ## Add swap memory (some packages require a lot of mem, such as lxml)
        cmds.append('dd if=/dev/zero of=/swapfile bs=1024 count=1000000')
        cmds.append('chmod 600 /swapfile')
        cmds.append('mkswap /swapfile')
        cmds.append('swapon /swapfile')

        if 'rodan_task_queue' in components:
            ## Install RabbitMQ: http://www.rabbitmq.com/install-debian.html
            cmds.append('apt-get install -y wget')
            cmds.append('echo "# RabbitMQ" >> /etc/apt/sources.list')
            cmds.append('echo "deb http://www.rabbitmq.com/debian/ testing main" >> /etc/apt/sources.list')
            cmds.append('cd /tmp && wget https://www.rabbitmq.com/rabbitmq-signing-key-public.asc')
            cmds.append('apt-key add /tmp/rabbitmq-signing-key-public.asc')
            cmds.append('apt-get -y update')
            cmds.append('apt-get -y install rabbitmq-server')
            # set up RabbitMQ vhost
            cmds.append('service rabbitmq-server start && rabbitmqctl add_user %(username)s %(password)s && rabbitmqctl add_vhost %(vhost)s && rabbitmqctl set_permissions -p %(vhost)s %(username)s ".*" ".*" ".*"' % {
                'username': args.amqp_user,
                'password': args.amqp_password,
                'vhost': args.amqp_vhost
            })

        if 'rodan_database' in components:
            ## Install PostgreSQL
            cmds.append('apt-get -y install postgresql postgresql-contrib')
            ## Install PostgreSQL Python language
            cmds.append('apt-get -y install postgresql-plpython')
            ## Redis server
            cmds.append('apt-get -y install redis-server')
            ## Redis-Python binding
            cmds.append('apt-get -y install python-pip')
            cmds.append('pip install redis')
            ## Configure NORMAL user
            cmds.append("""service postgresql start && sudo -u postgres psql --command "create user %(user)s with password '%(password)s'; alter user %(user)s with createdb;" && sudo -u postgres psql --command 'create database %(name)s;' && sudo -u postgres psql --command 'grant all privileges on database "%(name)s" to %(user)s;'""" % {
                'name': args.db_name,
                'user': args.db_user,
                'password': args.db_password
            })
            ## expose PostgreSQL to allow access from workers' and server's subnet as normal user
            cmds.append("""echo "listen_addresses = '*'" >> /etc/postgresql/9.3/main/postgresql.conf && echo "#host  @DB_NAME@  @DB_USER@  @WORKERS_SUBNET@  md5" >> /etc/postgresql/9.3/main/pg_hba.conf""")
            for machine_number in set(components_distribution['rodan_worker']+components_distribution['rodan_web_server']):
                ip = ips_cleaned[machine_number]
                cmds.append("""echo "host  %(name)s  %(user)s  %(ip)s/32  md5" >> /etc/postgresql/9.3/main/pg_hba.conf""" % {
                    'name': args.db_name,
                    'user': args.db_user,
                    'ip': ip
                })
            ## Configure SUPERUSER
            cmds.append("""service postgresql start && sudo -u postgres psql --command "create user %(su_user)s with password '%(su_password)s'; alter user %(su_user)s with superuser;" """ % {
                'su_user': args.db_su_user,
                'su_password': args.db_su_password
            })
            ## expose PostgreSQL to allow access from server as super user
            for machine_number in set(components_distribution['rodan_web_server']):
                ip = ips_cleaned[machine_number]
                cmds.append("""echo "host  %(name)s  %(su_user)s  %(ip)s/32  md5" >> /etc/postgresql/9.3/main/pg_hba.conf""" % {
                    'name': args.db_name,
                    'su_user': args.db_su_user,
                    'ip': ip
                })
            cmds.append('service postgresql restart')
            ## expose Redis to allow access from server
            cmds.append("cat /etc/redis/redis.conf | sed '/^bind / d' > /etc/redis/redis.conf") # bind to all interfaces
            cmds.append('iptables -I INPUT -p tcp --dport 6379 -j DROP')
            for machine_number in set(components_distribution['rodan_web_server']):
                ip = ips_cleaned[machine_number]
                cmds.append('iptables -I INPUT -p tcp --dport 6379 -s {0} -j ACCEPT'.format(ip))
                cmds.append('iptables -I OUTPUT -p tcp --sport 6379 -d {0} -j ACCEPT'.format(ip))
            cmds.append('iptables-save & ufw reload & iptables -F')

        if 'rodan_resource_file_server' in components:
            # Check kernel modules
            cmds.append('modprobe nfs && modprobe nfsd')
            # Install NFS packages
            cmds.append('apt-get -y install nfs-common inotify-tools nfs-kernel-server runit')
            # set /etc/exports, expose the folder to workers' and server's subnet
            accesses = []
            for machine_number in set(components_distribution['rodan_worker']+components_distribution['rodan_web_server']):
                ip = ips_cleaned[machine_number]
                accesses.append("{0}(rw,sync,fsid=0,no_subtree_check,no_root_squash)".format(ip))
            cmds.append("mkdir -p {0}".format(args.nfs_server_directory))
            cmds.append("""echo "{0} {1}" >> /etc/exports""".format(args.nfs_server_directory, ' '.join(accesses)))
            cmds.append('service nfs-kernel-server restart')


        if 'rodan_worker' in components or 'rodan_web_server' in components:
            # worker and server share a lot of setting up codes.
            # set up Python environment
            cmds.append("apt-get -y install python2.7 git-core python-pip wget autoconf")
            # Set up app directory and Python virtual environment (copy Rodan source files later)
            cmds.append("mkdir -p {0}".format(args.rodan_app_directory))
            cmds.append("cd {0} && pip install virtualenv && virtualenv --no-site-packages rodan_env".format(args.rodan_app_directory))
            # Install Python packages
            cmds.append("apt-get -y install libpython-dev lib32ncurses5-dev libxml2-dev libxslt1-dev zlib1g-dev lib32z1-dev libjpeg-dev libpq-dev")
            cmds.append("cp {0}Rodan/requirements.txt /tmp/requirements.txt".format(args.package_src_directory))
            cmds.append("source {0}rodan_env/bin/activate && pip install -r /tmp/requirements.txt && deactivate".format(args.rodan_app_directory))

            # Compile packages
            cmds.append("mkdir -p {0} && chmod 755 {0}".format(args.package_src_directory))
            ## Install Gamera
            cmds.append("apt-get -y install libpng-dev libtiff-dev")
            cmds.append("""cd {0} && wget "http://sourceforge.net/projects/gamera/files/gamera/gamera-3.4.2/gamera-3.4.2.tar.gz/download" -O gamera-3.4.2.tar.gz && tar xvf gamera-3.4.2.tar.gz && source {1}rodan_env/bin/activate && cd gamera-3.4.2 && python setup.py install --nowx && deactivate""".format(args.package_src_directory, args.rodan_app_directory))
            cmds.append("""cd {0} && wget http://gamera.informatik.hsnr.de/addons/musicstaves/musicstaves-1.3.10.tar.gz && tar xvf musicstaves-1.3.10.tar.gz && source {1}rodan_env/bin/activate && cd musicstaves-1.3.10 && export CFLAGS="-I{0}gamera-3.4.2/include" && python setup.py install && deactivate""".format(args.package_src_directory, args.rodan_app_directory))
            cmds.append("""cd {0} && git clone https://github.com/DDMAL/document-preprocessing-toolkit.git && cd document-preprocessing-toolkit && source {1}rodan_env/bin/activate && export CFLAGS="-I{0}gamera-3.4.2/include" && cd background-estimation && python setup.py install && cd ../border-removal && python setup.py install && cd ../staffline-removal && python setup.py install && cd ../lyric-extraction && python setup.py install && deactivate""".format(args.package_src_directory, args.rodan_app_directory))
            cmds.append("""cd {0} && git clone https://github.com/DDMAL/rodan_plugins.git && cd rodan_plugins && source {1}rodan_env/bin/activate && export CFLAGS="-I{0}gamera-3.4.2/include" && python setup.py build && python setup.py install && deactivate""".format(args.package_src_directory, args.rodan_app_directory))

            ## Install LibMEI
            cmds.append("cp {0}Rodan/helper_scripts/neumes_and_layout_compiled.xml /tmp".format(args.package_src_directory))
            cmds.append("""cd {0} && git clone https://github.com/DDMAL/libmei.git && \
            cd libmei/tools && \
            pip install lxml && \
            python parseschema2.py -o src -l cpp /tmp/neumes_and_layout_compiled.xml && \
            python parseschema2.py -o src -l python /tmp/neumes_and_layout_compiled.xml && \
            rm -rf ../src/modules/* && \
            rm -rf ../python/pymei/Modules/* && \
            mv src/cpp/* ../src/modules/ && \
            mv src/python/* ../python/pymei/Modules/ && \
            apt-get -y install uuid-dev libxml2-dev cmake && \
            cd .. && \
            mkdir build && \
            cd build && \
            cmake .. && \
            make && \
            make install""".format(args.package_src_directory))
            cmds.append("""cd {0} && apt-get -y install build-essential python-dev python-setuptools libboost-python-dev libboost-thread-dev && \
            cd libmei/python && \
            wget https://gist.githubusercontent.com/lingxiaoyang/3e50398e9fef44b62206/raw/75706f28b9eef76635ca24be6d5f1b90fa5e40de/setup.py.patch && \
            patch setup.py < setup.py.patch && \
            source {1}rodan_env/bin/activate && \
            python setup.py install && deactivate""".format(args.package_src_directory, args.rodan_app_directory))

            ## xmllint
            cmds.append("""apt-get -y install libxml2-utils""")
            ## vips
            cmds.append("""apt-get -y install libvips-tools""")

            if not args.disable_diva:
                ## Graphics Magick
                cmds.append("""apt-get -y install graphicsmagick-imagemagick-compat""")

                ## Kakadu
                cmds.append("""apt-get -y install unzip""")
                cmds.append("""cd {0} && unzip v7_7-01273N.zip""".format(args.package_src_directory))
                cmds.append("""cd {0} && cd v7_7-01273N/coresys/make && make -f Makefile-Linux-x86-64-gcc""".format(args.package_src_directory))
                cmds.append("""cd {0} && cd v7_7-01273N/apps/make && make -f Makefile-Linux-x86-64-gcc""".format(args.package_src_directory))
                cmds.append("""cd {0} && cp v7_7-01273N/lib/Linux-x86-64-gcc/* /usr/local/lib && cp v7_7-01273N/bin/Linux-x86-64-gcc/* /usr/local/bin""".format(args.package_src_directory))

                if 'rodan_web_server' in components:
                    ## IIP Server
                    cmds.append("""cd {0} && git clone https://github.com/ruven/iipsrv.git && apt-get -y install libmemcached-dev libtool && cd iipsrv && ./autogen.sh && ./configure --with-kakadu={0}v7_7-01273N && make -j4 && mkdir -p /srv/fcgi-bin && cp src/iipsrv.fcgi /srv/fcgi-bin""".format(args.package_src_directory))

            # Install NFS client
            cmds.append("""apt-get -y install nfs-common inotify-tools""")
            ## Set mount point permissions
            cmds.append("""mkdir -p {0} && chown www-data:www-data {0}""".format(args.rodan_data_mount_point))

            # Copy Rodan source code
            cmds.append("""cp -av {0}Rodan/* {1}""".format(args.package_src_directory, args.rodan_app_directory))

            # Update Python requirements
            cmds.append("""cd {0} && source {0}rodan_env/bin/activate && pip install -r requirements.txt && deactivate""".format(args.rodan_app_directory))

            # Configure Rodan
            cmds.append("""cd {0} && autoconf""".format(args.rodan_app_directory))
            params = [
                '--enable-debug={0}'.format('yes' if args.debug else 'no'),
                '--disable-diva' if args.disable_diva else '--enable-diva',
                'MODE={0}'.format('server' if 'rodan_web_server' in components else 'worker'),
                'RODAN_VENV_DIR={0}rodan_env'.format(args.rodan_app_directory),
                'RODAN_DATA_DIR={0}'.format(args.rodan_data_mount_point),
                'AMQP_HOST={0}'.format(ips_cleaned[components_distribution['rodan_task_queue'][0]]),
                'AMQP_PORT=5672',
                'AMQP_VHOST={0}'.format(args.amqp_vhost),
                'AMQP_USER={0}'.format(args.amqp_user),
                'AMQP_PASSWORD={0}'.format(args.amqp_password),
                'DB_HOST={0}'.format(ips_cleaned[components_distribution['rodan_database'][0]]),
                'DB_PORT=5432',
                'DB_NAME={0}'.format(args.db_name),
                'DB_USER={0}'.format(args.db_user),
                'DB_PASSWORD={0}'.format(args.db_password),
                'DB_SU_USER={0}'.format(args.db_su_user),
                'DB_SU_PASSWORD={0}'.format(args.db_su_password),
                'REDIS_HOST={0}'.format(ips_cleaned[components_distribution['rodan_database'][0]]),
                'REDIS_PORT=6379',
                'REDIS_DB=0',
                'WWW_USER=www-data',
                'WWW_GROUP=www-data',
                'DOMAIN_NAME={0}'.format(args.server_domain_name) if 'rodan_web_server' in components else "",
                'CLIENT_MAX_BODY_SIZE={0}'.format(args.server_client_max_body_size) if 'rodan_web_server' in components else "",
                'SECRET_KEY={0}'.format(''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(40))),
                'SSL_CERT={0}'.format(args.server_ssl_cert_path) if 'rodan_web_server' in components else "",
                'SSL_CERT_KEY={0}'.format(args.server_ssl_cert_key_path) if 'rodan_web_server' in components else "",
                'IIPSRV_FCGI=/srv/fcgi-bin/iipsrv.fcgi' if not args.disable_diva and 'rodan_web_server' in components else "",
                'PAGINATE_BY={0}'.format(args.server_paginate_by),
            ]
            cmds.append("""cd {0} && ./configure {1}""".format(args.rodan_app_directory, ' '.join(params)))

            # Install supervisor
            cmds.append("""apt-get -y install supervisor""")
            cmds.append("""cp {0}etc/supervisor/conf.d/rodan.conf /etc/supervisor/conf.d/""".format(args.rodan_app_directory))

            if 'rodan_web_server' in components:
                # Install nginx
                cmds.append("""apt-get -y install nginx""")
                cmds.append("""rm -f /etc/nginx/sites-enabled/rodan && cp {0}etc/nginx/sites-available/rodan /etc/nginx/sites-available && ln -s /etc/nginx/sites-available/rodan /etc/nginx/sites-enabled/rodan""".format(args.rodan_app_directory))

                # Initialize database
                cmds.append("""cd {0} && source {0}rodan_env/bin/activate && RODAN_PSQL_SUPERUSER_USERNAME={1} RODAN_PSQL_SUPERUSER_PASSWORD={2} python manage.py migrate && echo "from django.contrib.auth.models import User; User.objects.create_superuser('{3}', '', '{4}')" | python manage.py shell && deactivate""".format(
                    args.rodan_app_directory,
                    args.db_su_user,
                    args.db_su_password,
                    args.rodan_admin_user,
                    args.rodan_admin_password
                ))

                # [TODO] additional configuration for CORS
            # Set Rodan dir permission
            cmds.append('chown -R www-data:www-data {0}'.format(args.rodan_app_directory))

        ######### AUTOSTART commands #########
        if 'rodan_task_queue' in components:
            cmds.append('update-rc.d rabbitmq-server defaults; true')
        if 'rodan_database' in components:
            cmds.append('update-rc.d postgresql defaults; true')
            cmds.append('update-rc.d redis-server defaults; true')
        if 'rodan_resource_file_server' in components:
            cmds.append('update-rc.d rpcbind defaults; true')
            cmds.append('update-rc.d nfs-kernel-server defaults; true')
        if 'rodan_worker' in components or 'rodan_web_server' in components:
            if 'rodan_web_server' in components:
                cmds.append('update-rc.d nginx defaults; true')
            cmds.append('update-rc.d rpcbind defaults; true')
            cmds.append('update-rc.d supervisor defaults; true')
            cmds.append('echo "%(nfs_server_ip)s:/ %(rodan_data_mount_point)s nfs auto,noatime,nolock,bg,nfsvers=4,intr,tcp,port=2049,actimeo=1800 0 0" >> /etc/fstab' % {
                'nfs_server_ip': ips_cleaned[components_distribution['rodan_resource_file_server'][0]], # [TODO] localhost IP
                'rodan_data_mount_point': args.rodan_data_mount_point
            })
            cmds.append('mount {0}'.format(args.rodan_data_mount_point))
            cmds.append('chown -R www-data:www-data {0}'.format(args.rodan_data_mount_point))  # change permission of the mount folder

        cmds.append('swapoff /swapfile')
        cmds.append('reboot')
        shell_commands.append(cmds)

    ## generate script files
    for i, components in enumerate(components_cleaned):
        script_filename = os.path.join(args.output_folder, "{0}.sh".format(i+1))
        with open(script_filename, 'w') as g:
            # file head
            g.write("""#!/bin/bash
set -e
if test "$EUID" -ne 0; then
  echo "Please run as root"
  exit 1
fi\n""")
            g.write("\n".join(shell_commands[i])+"\n")

        # add executable permission
        st = os.stat(script_filename)
        os.chmod(script_filename, st.st_mode | stat.S_IEXEC)

        MSG_NOTICE("Wrote {0}".format(script_filename))

    # generate Vagrantfile
    vfile_name = os.path.join(args.output_folder, "Vagrantfile")
    with open(vfile_name, 'w') as g:
        g.write('Vagrant.configure("2") do |config|\n')
        g.write('  config.vm.provision "shell", inline: "echo Rodan Deployment Test"\n')
        g.write('  config.vm.box = "ubuntu/trusty64"\n')

        for i, components in enumerate(components_cleaned):
            g.write('\n')
            g.write('  config.vm.define "m{0}" do |m|\n'.format(i+1))
            if i in components_distribution['rodan_web_server']:
                g.write('    m.vm.network "forwarded_port", guest: 80, host: 8080\n')
                g.write('    m.vm.network "forwarded_port", guest: 443, host: 8443\n')
            #if i in components_distribution['rodan_web_server'] or i in components_distribution['rodan_worker']:
            #    g.write('    m.vm.provider "virtualbox" do |vb|\n')
            #    g.write('      vb.memory="1024"\n')
            #    g.write('    end\n')
            g.write('    m.vm.network "private_network", ip: "{0}"\n'.format(ips_cleaned[i]))
            g.write('    m.vm.provision "shell", inline: <<-SHELL\n')
            g.write('      mkdir -p {0}\n'.format(args.package_src_directory))
            g.write('      cp -av /vagrant/Rodan {0}\n'.format(args.package_src_directory))
            if not args.disable_diva:
                g.write('      cp /vagrant/v7_7-01273N.zip {0}\n'.format(args.package_src_directory))
            # Copy SSL cert and key
            g.write('      mkdir -p `dirname {0}`\n'.format(args.server_ssl_cert_path))
            g.write('      cp /vagrant/rodan.crt {0}\n'.format(args.server_ssl_cert_path))
            g.write('      mkdir -p `dirname {0}`\n'.format(args.server_ssl_cert_key_path))
            g.write('      cp /vagrant/rodan.key {0}\n'.format(args.server_ssl_cert_key_path))
            g.write('    SHELL\n')
            g.write('    m.vm.provision "shell" do |shell|\n')
            g.write('      shell.path = "{0}.sh"\n'.format(i+1))
            g.write('    end\n')
            g.write('  end\n')
        g.write('end\n')

    MSG_NOTICE("Wrote {0}".format(vfile_name))
    MSG_NOTICE("Visit https://127.0.0.1:8080 after vagrant up")


if __name__ == "__main__":
    main()
