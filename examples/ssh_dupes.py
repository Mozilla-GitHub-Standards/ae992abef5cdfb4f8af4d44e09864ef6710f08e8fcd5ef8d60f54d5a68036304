#!/usr/bin/env python2
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2014 Mozilla Corporation
# Author: gdestuynder@mozilla.com
#
# Check if there are duplicate ssh keys in LDAP, i.e. shared keys

# Requires:
# mozlibldap

import mozlibldap

LDAP_URL='ldaps://'
LDAP_BIND_DN=''
LDAP_BIND_PASSWD=''

def main():
		l = mozlibldap.MozLDAP(LDAP_URL, LDAP_BIND_DN, LDAP_BIND_PASSWD)
		all_keys = {}
		invalid = []

		x = l.get_all_enabled_users_attr('sshPublicKey')
		for user in x:
			dn = user[0]
			keys = user[1]
			if len(keys) != 0:
				for k in keys['sshPublicKey']:
					try:
						i = k.split(' ')[1]
						if all_keys.has_key(i):
							all_keys[i] += [dn]
						else:
							all_keys[i] = [dn]
					except:
						invalid += [dn, keys]

		for k in all_keys:
			if len(all_keys[k]) > 1:
				print("duplicate keys", all_keys[k])

if __name__ == "__main__":
	main()
