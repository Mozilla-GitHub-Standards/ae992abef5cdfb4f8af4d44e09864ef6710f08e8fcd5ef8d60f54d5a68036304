#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2015 Mozilla Corporation
# Author: jvehent@mozilla.com

# Requires:
# mozlibldap

import mozlibldap
import string
import json

LDAP_URL = 'ldap://ldap.db.scl3.mozilla.com'
LDAP_BIND_DN = 'mail=bob.kelso@mozilla.com,o=com,dc=mozilla'
LDAP_BIND_PASSWD = "mysecretpassword"


def main():
    lcli = mozlibldap.MozLDAP(LDAP_URL, LDAP_BIND_DN, LDAP_BIND_PASSWD)

    searches = {}
    for user in ['ffxbld', 'b2gbld', 'tbirdbld', 'xrbld', 'pvtbld', 'b2gtry',
                 'tbirdtry', 'trybld']:
        searches[user+"_ssh_pubkeys"] = {}
        searches[user+"_ssh_pubkeys"]["names"] = []
        searches[user+"_ssh_pubkeys"]["names"].append("^authorized_keys$")
        searches[user+"_ssh_pubkeys"]["contents"] = []
        searches[user+"_ssh_pubkeys"]["contents"].append(
            get_pubkeys_regex(lcli, user))
        searches[user+"_ssh_pubkeys"]["paths"] = get_search_paths(lcli, user)
        searches[user+"_ssh_pubkeys"]["options"] = {}
        searches[user+"_ssh_pubkeys"]["options"]["matchall"] = True
        searches[user+"_ssh_pubkeys"]["options"]["macroal"] = True
        searches[user+"_ssh_pubkeys"]["options"]["maxdepth"] = 1
        searches[user+"_ssh_pubkeys"]["options"]["mismatch"] = []
        searches[user+"_ssh_pubkeys"]["options"]["mismatch"].append("content")
    action = {}
    action["name"] = "Assert the content of authorized_keys for builder users"
    action["target"] = "tags->>'operator'='IT' AND status='online'"
    action["version"] = 2
    action["operations"] = []
    operation = {}
    operation["module"] = "file"
    operation["parameters"] = {}
    operation["parameters"]["searches"] = searches
    action["operations"].append(operation)
    print(json.dumps(action, indent=4, sort_keys=True))


def get_pubkeys_regex(lcli, user):
    pubkeys = lcli.get_user_attribute(
        "uid={user}".format(user=user), "sshPublicKey")
    contentre = '^((#.+)|(\s+)'
    for pubkey in pubkeys:
        # only keep the first 2 parts, ignore the comment
        # and escape some characters
        pubkey = string.join(pubkey.split(' ', 2)[:2], '\s')
        pubkey = pubkey.replace('/', '\/')
        pubkey = pubkey.replace('+', '\+')
        contentre += '|({pubkey}\s.+)'.format(pubkey=pubkey)
    contentre += ')$'
    return contentre


def get_search_paths(lcli, user):
    paths = []
    for home in ['homeDirectory', 'hgHome', 'fakeHome',
                 'stageHome', 'svnHome']:
        try:
            path = lcli.get_user_attribute(
                "uid={user}".format(user=user), home)
        except:
            continue
        if path:
            paths.append(path[0]+"/.ssh")
    return paths


if __name__ == "__main__":
    main()
