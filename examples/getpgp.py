#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2015 Mozilla Corporation
# Author: jvehent@mozilla.com

# Requires:
# mozlibldap

import mozlibldap

LDAP_URL='ldap://ldap.db.scl3.mozilla.com'
LDAP_BIND_DN='mail=spongebob@mozilla.com,o=com,dc=mozilla'
LDAP_BIND_PASSWD='CaribouMaurice'

def main():
    lcli = mozlibldap.MozLDAP(LDAP_URL, LDAP_BIND_DN, LDAP_BIND_PASSWD)

    # get all the pgp fingerprints of users in the sysadmins group
    res = lcli.get_pgp_in_group("sysadmins")
    for member, fp in res:
        print member + " " + fp

    # get the pgp fingeprint of a single user
    print lcli.get_user_attribute("mail=jvehent@mozilla.com", "pgpFingerprint")[0]

if __name__ == "__main__":
    main()
