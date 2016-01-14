Deployment tool for [Rodan](https://github.com/DDMAL/Rodan) on a cluster.


Usage
=====

1. Prepare a subnet of clean Ubuntu 14.04 machines as the cluster. (Note: we only support Ubuntu 14.04 for now. Other Ubuntu versions may work but have not been tested.)

2. Assign the roles of the machines according to [Rodan architecture](https://raw.githubusercontent.com/wiki/DDMAL/Rodan/images/installation_1.png), as one (or a combination) of: web server, worker, database, task queue, and/or resource file server.

3. Assign static IP addresses for all machines. Open HTTP and HTTPS ports on the web server.

4. Run `configure.py`. An example usage is shown below. You can modify the configuration parameters according to the information given by `python configure.py --help`.

````
python configure.py \
  --output-folder build \
  --os ubuntu:14.04 \
  --db-password hahaha \
  --db-su-password hahahasu \
  --nfs-server-directory /data \
  --server-domain-name rodan-dev.simssa.ca \
  --server-paginate-by 50 \
  --server-client-max-body-size 500M \
  --server-ssl-cert-path /etc/ssl/rodan.crt \
  --server-ssl-cert-key-path /etc/ssl/rodan.key \
  --rodan-app-directory /srv/webapps/Rodan \
  --rodan-data-mount-point /mnt/rodan_data \
  --package-src-directory /root/src \
  --rodan-admin-user admin \
  --rodan-admin-password hahaha \
  rodan_task_queue@192.168.1.100 \
  rodan_database+rodan_resource_file_server@192.168.1.101 \
  rodan_worker+rodan_web_server@192.168.1.102 \
  rodan_worker@192.168.1.103
````

5. The script will generate an output folder. In this folder, you will find `configuration.json` that stores all parameters and machine configurations. You will also find `{i}.sh` and `Vagrantfile`.

6a. For testing purposes, copy necessary files into this output folder as explained below. Then install Vagrant and run `vagrant up` in the same folder. ([SSL certificate guide](http://www.akadia.com/services/ssh_test_certificate.html))

````
- Rodan             a folder that stores Rodan code. You can: git clone --recursive https://github.com/DDMAL/Rodan.git
- v7_7-01273N.zip   Kakadu source code. If you do not disable Diva.js, you will need to provide this proprietary package.
- rodan.crt         SSL certificate for the HTTPS server. (Rodan enforces HTTPS.)
- rodan.key         SSL certificate private key for the HTTPS server.
````

6b. For production, distribute all `{i}.sh` to corresponding machines. On the web server and the workers, the files listed in Step 6a should be prepared in the `package-src-directory` set in Step 4.


Troubleshoot - Testing in Vagrant
=================================

**I see a red message during `vagrant up` that says:**

````
==> m3: stdin: is not a tty
````
or
````
==> m3: dpkg-preconfigure: unable to re-open stdin: No such file or directory
````

It is a known problem of Vagrant with Ubuntu. Ignore these messages as they do not affect the execution of commands.


**I receive red messages in the beginning of `vagrant up` as below.**
````
==> m3: cp:
==> m3: cannot /vagrant/
==> m3: : No such file or directory
==> m3: cp:
==> m3: cannot /vagrant/v7_7-01273N.
==> m3: : No such file or directory
==> m3: cp:
==> m3: cannot /vagrant/rodan.
==> m3: : No such file or directory
==> m3: cp:
==> m3: cannot /vagrant/rodan.
==> m3: : No such file or directory
````

You need to provide necessary files in the output folder as listed in Step 6a.


**I receive the following error message when I run `vagrant up`.**

````
Vagrant cannot forward the specified ports on this VM, since they
would collide with some other application that is already listening
on these ports. The forwarded port to 8080 is already in use
on the host machine.

To fix this, modify your current project's Vagrantfile to use another
port. Example, where '1234' would be replaced by a unique host port:

  config.vm.network :forwarded_port, guest: 80, host: 1234

Sometimes, Vagrant will attempt to auto-correct this for you. In this
case, Vagrant was unable to. This is usually because the guest machine
is in a state which doesn't allow modifying port forwarding.
````

There is a collision in regards to the port forwarding. By default, the `Vagrantfile` requires the port 8080 on the host machine, and when this port is occupied, Vagrant prompts the message above. The port forwarding is only defined on the web server VM, and thus you will need to manually find and change this port in `Vagrantfile`.
