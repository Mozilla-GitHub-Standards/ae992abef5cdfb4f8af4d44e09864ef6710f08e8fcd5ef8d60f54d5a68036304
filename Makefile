# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2014 Mozilla Corporation
# Author: gdestuynder@mozilla.com

all:
	./setup.py build

install:
	./setup.py install

test:
	./unittests.py

rpm:
	fpm -s python -t rpm ./setup.py

deb:
	fpm -s python -t deb ./setup.py

pypi:
	python setup.py sdist check upload --sign

clean:
	rm -rf *pyc
	rm -rf build
	rm -rf __pycache__
	rm -rf examples/__pycache__
	rm -rf examples/*pyc
