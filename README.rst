File Integrity Monitoring (FIM) Execution Module
================================================

In a nutshell, this module collects FIM data from a minion. Collected data
includes:

- hashing algorithm
- file atime
- file checksum
- file ctime
- file gid / group
- file inode
- file mode (permissions)
- file mtime
- file size
- file target (full path)
- file type
- file uid / user

Runtime
-------

This module is flexible regarding what data is captured, and how it is
returned. Primary options (runtime or configured) include:

- algo (md5, sha1, sha224, sha256 (default), sha384, sha512)
- targets (file or directory path. directories will be recursed)
- filename (output filename to save compressed (gzip) output)

CLI Example:

.. code-block:: shell

    salt '*' fim.checksum algo='sha1' targets='['/usr/sbin/sshd', '/etc']'

    salt '*' fim.checksum targets='['/bin', '/sbin', '/usr/bin', '/usr/sbin']'

    salt '*' fim.checksum targets='['/etc']' filename='/var/log/salt/fim.log.gz'

Example #1: use sha1 hash algorithm to recursively hash the defined targets
list.

Example #2: use default hash algorithm to recursively hash defined targets
list.

Example #3: use default hash algorithm to recursively hash defined targets list
and write to defined filename path.


Configuration
-------------

An example config file, (`/etc/salt/minion.d/fim.conf`) for this module
could look something like this:

.. code-block:: yaml

    fim:
      algo: sha256
      filename: /var/log/salt/fim.log.gz
      targets:
        - /bin
        - /sbin
        - /usr/bin
        - /usr/sbin
        - /usr/local/bin
        - /usr/local/sbin


