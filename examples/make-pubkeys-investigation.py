#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2015 Mozilla Corporation
# Author: jvehent@mozilla.com

# Requires:
# mozlibldap

from __future__ import print_function
import mozlibldap
import string
import json
import sys

LDAP_URL = 'ldap://ldap.db.scl3.mozilla.com'
LDAP_BIND_DN = 'mail=bob.kelso@mozilla.com,o=com,dc=mozilla'
LDAP_BIND_PASSWD = "mysecretpassphrase"


def main():
    lcli = mozlibldap.MozLDAP(LDAP_URL, LDAP_BIND_DN, LDAP_BIND_PASSWD)
    searches = {}

    # get a list of users that have a pubkey in ldap
    users = lcli.get_all_enabled_users_attr('sshPublicKey')
    for user_attr in users:
        search = {}
        user = user_attr[0].split(',', 1)[0].split('=', 1)[1]
        print("current user: "+user, file=sys.stderr)
        keys = user_attr[1]
        if len(keys) == 0:
            continue
        contentre = '^((#.+)|(\s+)'
        for pubkey in keys['sshPublicKey']:
            if len(pubkey) < 5 or not (pubkey.startswith("ssh")):
                continue
            pubkey = string.join(pubkey.split(' ', 2)[:2], '\s')
            pubkey = pubkey.replace('/', '\/')
            pubkey = pubkey.replace('+', '\+')
            pubkey = pubkey.replace('\r\n', '')
            contentre += '|({pubkey}\s.+)'.format(pubkey=pubkey)
        contentre += ')$'
        search["names"] = []
        search["names"].append("^authorized_keys$")
        search["contents"] = []
        search["contents"].append(contentre)
        paths = []
        try:
            paths = get_search_paths(lcli, user)
        except:
            continue
        if not paths or len(paths) < 1:
            continue
        search["paths"] = paths
        search["options"] = {}
        search["options"]["matchall"] = True
        search["options"]["macroal"] = True
        search["options"]["maxdepth"] = 1
        search["options"]["mismatch"] = []
        search["options"]["mismatch"].append("content")
        print(json.dumps(search), file=sys.stderr)
        searches[user+"_ssh_pubkeys"] = search
    action = {}
    action["name"] = "Investigate the content of authorized_keys for LDAP users"
    action["target"] = "(name LIKE 'admin%' OR name LIKE 'ssh%' " + \
            "OR name LIKE 'people%' OR name LIKE 'zlb%' OR name IN " + \
            "('reviewboard-hg1.dmz.scl3.mozilla.com', 'hgssh.stage.dmz.scl3.mozilla.com', " + \
            "'hgssh1.dmz.scl3.mozilla.com', 'hgssh2.dmz.scl3.mozilla.com', " + \
            "'git1.dmz.scl3.mozilla.com', 'git1.private.scl3.mozilla.com', " + \
            "'svn1.dmz.phx1.mozilla.com', 'svn2.dmz.phx1.mozilla.com', " + \
            "'svn3.dmz.phx1.mozilla.com')) AND tags->>'operator'='IT' AND " + \
            "mode='daemon' AND status='online'"
    action["version"] = 2
    action["operations"] = []
    operation = {}
    operation["module"] = "file"
    operation["parameters"] = {}
    operation["parameters"]["searches"] = searches
    action["operations"].append(operation)
    print(json.dumps(action, indent=4, sort_keys=True))


def get_search_paths(lcli, user):
    paths = []
    res = lcli.query("mail="+user, ['homeDirectory', 'hgHome',
                                    'stageHome', 'svnHome'])
    for attr in res[0][1]:
        try:
            paths.append(res[0][1][attr][0]+"/.ssh")
        except:
            continue
    return paths


if __name__ == "__main__":
    main()
