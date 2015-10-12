mozlibldap
==========

Python lib for common OpenLDAP queries @ Mozilla.
This only works with LDAP databases using a schema similar to Mozilla's.

Install
--------
Using pip
~~~~~~~~~

.. code::

	sudo apt-get install libldap2-dev libsasl2-dev
	pip install mozlibldap

As a python module
~~~~~~~~~~~~~~~~~~

Manually:
.. code::

    make install

As a rpm/deb package
.. code::

   make rpm
   make deb
   rpm -i <package.rpm>
   dpkg -i <package.deb>

Testing
~~~~~~~
Fill in the LDAP URL, login, password in tests.py and run it :)

From the code/integrate in my code
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Add to your project with:

.. code::

   git submodule add https://github.com/mozilla-it/mozlibldap
   git commit -a

Python dependencies
~~~~~~~~~~~~~~~~~~~

* python-ldap

Usage
-----

Login/pass:

.. code::

	import mozlibldap
	
	l = mozlibldap.MozLDAP(LDAP_URL, LDAP_BIND_DN, LDAP_BIND_PASSWD)
	print(l.get_user_posix_uid("gdestuynder@mozilla.com"))

With client certificate (the certificate DN needs to match your LDAP DN).
The client cert, key file and optional ca cert (last argument) are all PEM files.

.. code::

        import mozlibldap

	l = mozlibldap.MozLDAP(LDAP_URL, LDAP_BIND_DN, None, LDAP_BIND_CLIENTCERT, LDAP_BIND_KEYFILE)
        # If using a self-signed CA in a specific location, like Mozilla CA
	#l = mozlibldap.MozLDAP(LDAP_URL, LDAP_BIND_DN, None, LDAP_BIND_CLIENTCERT, LDAP_BIND_KEYFILE,
        #                       "/etc/ssl/mozca.pem")
	print(l.get_user_posix_uid("gdestuynder@mozilla.com"))
