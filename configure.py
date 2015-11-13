"""
Rodan Deployment Tool

Copyright 2011-2015 Distributed Digital Music Archives and Libraries Lab
"""
__version__ = '1.0.0'

RODAN_COMPONENTS = ('rodan_task_queue', 'rodan_database', 'rodan_resource_file_server', 'rodan_worker', 'rodan_web_server')

import argparse
import os, stat
import socket
import json
import random, string

def MSG_ERROR(msg):
    FAIL = '\033[91m'  # color code for red
    ENDC = '\033[0m'   # color code end
    print "{0}{1}{2}".format(FAIL, msg, ENDC)
    exit(1)

def MSG_NOTICE(msg):
    print msg

def RUN(cmd, script_type):
    "shortcut function as there are too many RUNs"
    if script_type == "bash":
        return cmd.strip()
    elif script_type == 'dockerfile':
        return "RUN     {0}".format(cmd.strip())

def COPY(src, dest, script_type):
    "shortcut function as there are too many COPY operations"
    if script_type == "bash":
        return "cp $BASE_DIR/{0} {1}".format(src, dest)
    elif script_type == 'dockerfile':
        return "COPY    {0} {1}".format(src, dest)


def main():
    parser = argparse.ArgumentParser(description='''
Generate bash scripts that install Rodan on distributed machines, or generate Dockerfiles that test Rodan deployment in distributed Docker containers.

Examples:
 TODO
''')
    parser.add_argument('--output-script-type', required=True, type=str, choices=('bash', 'dockerfile'), help="output script type")
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

    parser.add_argument('--server-domain-name', required=True, type=str, help="Rodan server domain name")
    parser.add_argument('--server-paginate-by', required=True, type=int, help="Rodan server PAGINATE_BY setting (the number of objects on a page)")
    parser.add_argument('--server-client-max-body-size', required=True, type=str, help="the maximum size of HTTP request that Rodan server will allow (e.g., 20M, 2G, or etc.). It should be related to the size of resource file.")
    parser.add_argument('--server-ssl-cert-path', required=True, type=str, help="Rodan server SSL certification path")
    parser.add_argument('--server-ssl-cert-key-path', required=True, type=str, help="Rodan server SSL certification key path")

    parser.add_argument('--rodan-app-directory', required=True, type=str, help="the directory on Rodan workers and web server that will contain Rodan code")
    parser.add_argument('--rodan-data-mount-point', required=True, type=str, help="where other Rodan workers and Rodan server mount the resource files")
    parser.add_argument('--package-src-directory', required=True, type=str, help="the directory on Rodan workers and web server that will contain the source codes of packages that Rodan require")
    parser.add_argument('--www-user', type=str, default="www-user", help="the Unix username that will run Rodan workers and web server")
    parser.add_argument('--www-group', type=str, default="www-group", help="the Unix user group that will run Rodan workers and web server")
    parser.add_argument('--rodan-admin-user', required=True, type=str, help="Rodan admin user name")
    parser.add_argument('--rodan-admin-password', required=True, type=str, help="Rodan admin user password")

    parser.add_argument('--debug', action='store_true', help="enable debug mode on Rodan server (not workers)")
    parser.add_argument('--disable-diva', action='store_true', help="disable Diva.js image viewer")


    args = parser.parse_args()

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

    ## write scripts
    for i, components in enumerate(components_cleaned):
        script_filename = os.path.join(args.output_folder, "{0}.{1}".format(i+1, args.output_script_type))
        with open(script_filename, 'w') as g:
            # file head
            if args.output_script_type == 'dockerfile':
                g.write('FROM    {0}:{1}\n'.format(os_name, os_version))
                ## For docker also uses bash instead of original sh (because of virtual environment)
                g.write("RUN     rm /bin/sh && ln -s /bin/bash /bin/sh\n")
            elif args.output_script_type == 'bash':
                g.write("""#!/bin/bash
set -e
if test "$EUID" -ne 0; then
  echo "Please run as root"
  exit 1
fi\n""")
                g.write("BASE_DIR=$(pwd)")  # store base dir

            ## update system
            g.write(RUN('apt-get -y update && apt-get -y upgrade', args.output_script_type)+"\n")

            if 'rodan_task_queue' in components:
                ## Install RabbitMQ: http://www.rabbitmq.com/install-debian.html
                g.write(RUN('apt-get install -y wget', args.output_script_type)+"\n")
                g.write(RUN('echo "# RabbitMQ" >> /etc/apt/sources.list', args.output_script_type)+"\n")
                g.write(RUN('echo "deb http://www.rabbitmq.com/debian/ testing main" >> /etc/apt/sources.list', args.output_script_type)+"\n")
                g.write(RUN('cd /tmp && wget https://www.rabbitmq.com/rabbitmq-signing-key-public.asc', args.output_script_type)+"\n")
                g.write(RUN('apt-key add /tmp/rabbitmq-signing-key-public.asc', args.output_script_type)+"\n")
                g.write(RUN('apt-get -y update', args.output_script_type)+"\n")
                g.write(RUN('apt-get -y install rabbitmq-server', args.output_script_type)+"\n")
                if args.output_script_type == "dockerfile":
                    ## Fix Celery node name (because Docker hostname is changing)
                    g.write(RUN('echo "NODENAME=rodan@{0}" >> /etc/rabbitmq/rabbitmq-env.conf'.format(ips_cleaned[i]), args.output_script_type)+"\n")

                # set up RabbitMQ vhost
                g.write(RUN('service rabbitmq-server start && rabbitmqctl add_user %(username)s %(password)s && rabbitmqctl add_vhost %(vhost)s && rabbitmqctl set_permissions -p %(vhost)s %(username)s ".*" ".*" ".*"' % {
                    'username': args.amqp_user,
                    'password': args.amqp_password,
                    'vhost': args.amqp_vhost
                }, args.output_script_type)+"\n")

                if args.output_script_type == 'dockerfile':
                    # expose docker ports
                    g.write('EXPOSE  5672\n')

            if 'rodan_database' in components:
                #g.write(RUN('apt-get -y install libpq-dev', args.output_script_type)+"\n")
                ## Install PostgreSQL
                g.write(RUN('apt-get -y install postgresql postgresql-contrib', args.output_script_type)+"\n")
                ## Install PostgreSQL Python language
                g.write(RUN('apt-get -y install postgresql-plpython', args.output_script_type)+"\n")
                ## Redis server
                g.write(RUN('apt-get -y install redis-server', args.output_script_type)+"\n")
                ## Configure NORMAL user
                g.write(RUN("""service postgresql start && sudo -u postgres psql --command "create user %(user)s with password '%(password)s'; alter user %(user)s with createdb;" && sudo -u postgres psql --command 'create database %(name)s;' && sudo -u postgres psql --command 'grant all privileges on database "%(name)s" to %(user)s;'""" % {
                    'name': args.db_name,
                    'user': args.db_user,
                    'password': args.db_password
                }, args.output_script_type)+"\n")
                ## expose PostgreSQL to allow access from workers' and server's subnet as normal user
                g.write(RUN("""echo "listen_addresses = '*'" >> /etc/postgresql/9.3/main/postgresql.conf && echo "host  @DB_NAME@  @DB_USER@  @WORKERS_SUBNET@  md5" >> /etc/postgresql/9.3/main/pg_hba.conf""", args.output_script_type)+"\n")
                for machine_number in set(components_distribution['rodan_worker']+components_distribution['rodan_web_server']):
                    ip = ips_cleaned[machine_number]
                    g.write(RUN("""echo "host  %(name)s  %(user)s  %(subnet)s  md5" >> /etc/postgresql/9.3/main/pg_hba.conf""" % {
                        'name': args.db_name,
                        'user': args.db_user,
                        'subnet': ip
                    }, args.output_script_type)+"\n")
                ## Configure SUPERUSER
                g.write(RUN("""service postgresql start && sudo -u postgres psql --command "create user %(su_user)s with password '%(su_password)s'; alter user %(su_user)s with superuser;" """ % {
                    'su_user': args.db_su_user,
                    'su_password': args.db_su_password
                }, args.output_script_type)+"\n")
                ## expose PostgreSQL to allow access from server as super user
                for machine_number in set(components_distribution['rodan_web_server']):
                    ip = ips_cleaned[machine_number]
                    g.write(RUN("""echo "host  %(name)s  %(su_user)s  %(subnet)s  md5" >> /etc/postgresql/9.3/main/pg_hba.conf""" % {
                        'name': args.db_name,
                        'su_user': args.db_su_user,
                        'subnet': ip
                    }, args.output_script_type)+"\n")

                if args.output_script_type == 'dockerfile':
                    # expose docker ports
                    g.write('EXPOSE  5432\n')
                    g.write('EXPOSE  6379\n')

            if 'rodan_resource_file_server' in components:
                # Check kernel modules
                g.write(RUN('modprobe nfs && modprobe nfsd', args.output_script_type)+"\n")
                # Install NFS packages
                g.write(RUN('apt-get -y install nfs-common inotify-tools nfs-kernel-server runit', args.output_script_type)+"\n")
                # set /etc/exports, expose the folder to workers' and server's subnet
                accesses = []
                for machine_number in set(components_distribution['rodan_worker']+components_distribution['rodan_web_server']):
                    ip = ips_cleaned[machine_number]
                    accesses.append("{0}(rw,sync,fsid=0,no_subtree_check,no_root_squash)".format(ip))
                g.write(RUN("""echo "{0} {1}" >> /etc/exports""".format(args.nfs_server_directory, ' '.join(accesses)), args.output_script_type)+"\n")

                if args.output_script_type == 'dockerfile':
                    # expose docker ports
                    g.write('EXPOSE  111/udp\n')
                    g.write('EXPOSE  2049/tcp\n')

            if 'rodan_worker' or 'rodan_web_server' in components:
                # worker and server share a lot of setting up codes.

                # check source code
                if args.output_script_type == 'bash':
                    g.write("""if test ! -d $BASE_DIR/Rodan; then
  echo "Please put Rodan source code under "Rodan" directory in this folder, and try again."
  exit 1;
fi
""")
                    g.write("""if test ! -f $BASE_DIR/Rodan/requirements.txt; then
  echo "Cannot find 'Rodan/requirements.txt'. Please check your Rodan source and try again."
  exit 1;
fi
""")
                    if not args.disable_diva:
                        # check kakadu 7.7
                        g.write("""if test ! -f $BASE_DIR/v7_7-01273N.zip; then
  echo "Cannot find 'v7_7-01273N.zip'. Please copy your Kakadu source here and try again."
  exit 1;
fi
""")

                # set up Python environment
                g.write(RUN("apt-get -y install python2.7 git-core python-pip wget autoconf", args.output_script_type)+"\n")
                # Set up app directory and Python virtual environment (copy Rodan source files later)
                g.write(RUN("mkdir -p {0}".format(args.rodan_app_directory), args.output_script_type)+"\n")
                g.write(RUN("cd {0} && pip install virtualenv && virtualenv --no-site-packages rodan_env".format(args.rodan_app_directory), args.output_script_type)+"\n")
                # Install Python packages
                g.write(RUN("apt-get -y install libpython-dev lib32ncurses5-dev libxml2-dev libxslt1-dev zlib1g-dev lib32z1-dev libjpeg-dev libpq-dev", args.output_script_type)+"\n")
                g.write(COPY("Rodan/requirements.txt", "/tmp/requirements.txt", args.output_script_type)+"\n")
                g.write(RUN("source {0}rodan_env/bin/activate && pip install -r /tmp/requirements.txt && deactivate".format(args.rodan_app_directory), args.output_script_type)+"\n")

                # Compile packages
                g.write(RUN("mkdir -p {0} && chmod 755 {0}".format(args.package_src_directory), args.output_script_type)+"\n")
                ## Install Gamera
                g.write(RUN("apt-get -y install libpng-dev libtiff-dev", args.output_script_type)+"\n")
                g.write(RUN("""cd {0} && wget "http://sourceforge.net/projects/gamera/files/gamera/gamera-3.4.2/gamera-3.4.2.tar.gz/download" -O gamera-3.4.2.tar.gz && tar xvf gamera-3.4.2.tar.gz && source {1}rodan_env/bin/activate && cd gamera-3.4.2 && python setup.py install --nowx && deactivate""".format(args.package_src_directory, args.rodan_app_directory), args.output_script_type)+"\n")
                g.write(RUN("""cd {0} && wget http://gamera.informatik.hsnr.de/addons/musicstaves/musicstaves-1.3.10.tar.gz && tar xvf musicstaves-1.3.10.tar.gz && source {1}rodan_env/bin/activate && cd musicstaves-1.3.10 && CFLAGS="-I/src/gamera-3.4.2/include" python setup.py install && deactivate""".format(args.package_src_directory, args.rodan_app_directory), args.output_script_type)+"\n")
                g.write(RUN("""cd {0} && git clone https://github.com/DDMAL/document-preprocessing-toolkit.git && cd document-preprocessing-toolkit && source {1}rodan_env/bin/activate && CFLAGS="-I/src/gamera-3.4.2/include" && cd background-estimation && python setup.py install && cd ../border-removal && python setup.py install && cd ../staffline-removal && python setup.py install && cd ../lyric-extraction && python setup.py install && deactivate""".format(args.package_src_directory, args.rodan_app_directory), args.output_script_type)+"\n")
                g.write(RUN("""cd {0} && git clone https://github.com/DDMAL/rodan_plugins.git && cd rodan_plugins && source {1}rodan_env/bin/activate && CFLAGS="-I/src/gamera-3.4.2/include" && python setup.py build && python setup.py install && deactivate""".format(args.package_src_directory, args.rodan_app_directory), args.output_script_type)+"\n")

                ## Install LibMEI
                g.write(COPY("Rodan/helper_scripts/neumes_and_layout_compiled.xml", "/tmp", args.output_script_type)+"\n")
                g.write(RUN("""cd {0} && git clone https://github.com/DDMAL/libmei.git && \
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
        make install""".format(args.package_src_directory), args.output_script_type)+"\n")
                g.write(RUN("""cd {0} && apt-get -y install build-essential python-dev python-setuptools libboost-python-dev libboost-thread-dev && \
        cd libmei/python && \
        wget https://gist.githubusercontent.com/lingxiaoyang/3e50398e9fef44b62206/raw/75706f28b9eef76635ca24be6d5f1b90fa5e40de/setup.py.patch && \
        patch setup.py < setup.py.patch && \
        source {1}rodan_env/bin/activate && \
        python setup.py install && deactivate""".format(args.package_src_directory, args.rodan_app_directory), args.output_script_type)+"\n")

                ## xmllint
                g.write(RUN("""apt-get -y install libxml2-utils""", args.output_script_type)+"\n")
                ## vips
                g.write(RUN("""apt-get -y install libvips-tools""", args.output_script_type)+"\n")

                if not args.disable_diva:
                    ## Graphics Magick
                    g.write(RUN("""apt-get -y install graphicsmagick-imagemagick-compat""", args.output_script_type)+"\n")

                    ## Kakadu
                    g.write(COPY("v7_7-01273N.zip", args.package_src_directory, args.output_script_type)+"\n")
                    g.write(RUN("""apt-get -y install unzip""", args.output_script_type)+"\n")
                    g.write(RUN("""cd {0} && unzip v7_7-01273N.zip""".format(args.package_src_directory), args.output_script_type)+"\n")
                    g.write(RUN("""cd {0} && cd v7_7-01273N/coresys/make && make -f Makefile-Linux-x86-64-gcc""".format(args.package_src_directory), args.output_script_type)+"\n")
                    g.write(RUN("""cd {0} && cd v7_7-01273N/apps/make && make -f Makefile-Linux-x86-64-gcc""".format(args.package_src_directory), args.output_script_type)+"\n")
                    g.write(RUN("""cd {0} && cp v7_7-01273N/lib/Linux-x86-64-gcc/* /usr/local/lib && cp v7_7-01273N/bin/Linux-x86-64-gcc/* /usr/local/bin""".format(args.package_src_directory), args.output_script_type)+"\n")

                    if 'rodan_web_server' in components:
                        ## IIP Server
                        g.write(RUN("""cd {0} && git clone https://github.com/ruven/iipsrv.git && apt-get -y install libmemcached-dev libtool && cd iipsrv && ./autogen.sh && ./configure --with-kakadu={0}v7_7-01273N && make -j4 && mkdir -p /srv/fcgi-bin && cp src/iipsrv.fcgi /srv/fcgi-bin""".format(args.package_src_directory), args.output_script_type)+"\n")

                # Install NFS client
                g.write(RUN("""apt-get -y install nfs-common inotify-tools""", args.output_script_type)+"\n")
                ## Set mount point permissions
                g.write(RUN("""mkdir -p {0} && chown {1}:{2} {0}""".format(args.rodan_data_mount_point, args.www_user, args.www_group), args.output_script_type)+"\n")

                # Update Rodan source code and Python requirements
                if args.output_script_type == 'dockerfile':
                    g.write("# For Docker: modify this 'echo' and trigger the update of Rodan source code.\n")
                    g.write('RUN     echo "Copying Rodan source..."\n')
                    g.write('COPY    Rodan {0}'.format(args.rodan_app_directory.rstrip('/'))+"\n")
                elif args.output_script_type == "bash":
                    g.write('cp -av $BASE_DIR/Rodan/* {0}'.format(args.rodan_app_directory)+"\n")
                g.write(RUN("""cd {0} && source {1}rodan_env/bin/activate && pip install -r requirements.txt && deactivate""".format(args.package_src_directory, args.rodan_app_directory), args.output_script_type)+"\n")

                # Configure Rodan
                g.write(RUN("""cd {0} && autoconf""".format(args.package_src_directory), args.output_script_type)+"\n")
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
                    'WWW_USER={0}'.format(args.www_user),
                    'WWW_GROUP={0}'.format(args.www_group),
                    'DOMAIN_NAME={0}'.format(args.server_domain_name) if 'rodan_web_server' in components else "",
                    'CLIENT_MAX_BODY_SIZE={0}'.format(args.server_client_max_body_size) if 'rodan_web_server' in components else "",
                    'SECRET_KEY={0}'.format(''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(40))),
                    'SSL_CERT={0}'.format(args.server_ssl_cert_path) if 'rodan_web_server' in components else "",
                    'SSL_CERT_KEY={0}'.format(args.server_ssl_cert_key_path) if 'rodan_web_server' in components else "",
                    'IIPSRV_FCGI=/srv/fcgi-bin/iipsrv.fcgi' if not args.disable_diva and 'rodan_web_server' in components else "",
                    'PAGINATE_BY={0}'.format(args.server_paginate_by),
                ]
                g.write(RUN("""cd {0} && ./configure {1}""".format(args.package_src_directory, ' '.join(params)), args.output_script_type)+"\n")

                # Install supervisor
                g.write(RUN("""apt-get -y install supervisor""", args.output_script_type)+"\n")
                g.write(RUN("""cp {0}etc/supervisor/conf.d/rodan.conf /etc/supervisor/conf.d/""".format(args.rodan_app_directory), args.output_script_type)+"\n")

                if 'rodan_web_server' in components:
                    # Install nginx
                    g.write(RUN("""apt-get -y install nginx""", args.output_script_type)+"\n")
                    g.write(RUN("""rm /etc/nginx/sites-enabled/rodan && cp {0}etc/nginx/sites-available/rodan /etc/nginx/sites-available && ln -s /etc/nginx/sites-available/rodan /etc/nginx/sites-enabled/rodan""".format(args.rodan_app_directory), args.output_script_type)+"\n")

                    # Initialize database
                    g.write(RUN("""cd {0} && service postgresql start && service redis-server start && source {0}rodan_env/bin/activate && RODAN_PSQL_SUPERUSER_USERNAME={1} RODAN_PSQL_SUPERUSER_PASSWORD={2} python manage.py migrate && echo "from django.contrib.auth.models import User; User.objects.create_superuser('{3}', '', '{4}')" | python manage.py shell && deactivate""".format(
                        args.rodan_app_directory,
                        args.db_su_user,
                        args.db_su_password,
                        args.rodan_admin_user,
                        args.rodan_admin_password
                    ), args.output_script_type)+"\n")

                    # [TODO] additional configuration for CORS

                    if 'rodan_web_server' in components:
                        # expose docker ports
                        g.write('EXPOSE  80\n')
                    # docker entrypoint
                    g.write('ENTRYPOINT  {0}\n'.format(' && '.join(entrypoint_cmds)))


            # docker entrypoint
            if args.output_script_type == 'dockerfile':
                entrypoint_cmds = []
                if 'rodan_task_queue' in components:
                    entrypoint_cmds.append('service rabbitmq-server start')
                if 'rodan_database' in components:
                    entrypoint_cmds.append('service postgresql start')
                    entrypoint_cmds.append('service redis-server start')
                if 'rodan_resource_file_server' in components:
                    entrypoint_cmds.append('service rpcbind start')
                    entrypoint_cmds.append('service nfs-kernel-server start')
                if 'rodan_worker' or 'rodan_web_server' in components:
                    if 'rodan_web_server' in components:
                        entrypoint_cmds.append('service nginx start')
                    entrypoint_cmds.append('service rpcbind start')
                    entrypoint_cmds.append('mount -t nfs -o proto=tcp,port=2049 %(nfs_server_ip)s:/ %(rodan_data_mount_point)s' % {
                        'nfs_server_ip': ips_cleaned[components_distribution['rodan_resource_file_server'][0]], # [TODO] localhost IP
                        'rodan_data_mount_point': args.rodan_data_mount_point
                    })
                g.write('ENTRYPOINT  {0}\n'.format(' && '.join(entrypoint_cmds)))


        # add executable permission
        st = os.stat(script_filename)
        os.chmod(script_filename, st.st_mode | stat.S_IEXEC)

        MSG_NOTICE("Wrote {0}".format(script_filename))


if __name__ == "__main__":
    main()
