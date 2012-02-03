#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

PACKAGE = trafficserver-plugins
VERSION = 3.0.0
distdir = $(PACKAGE)-$(VERSION)

TAR  = tar chof - "$$tardir"

SUBDIRS = balancer buffer_upload cacheurl combo_handler esi geoip_acl \
		  header_filter hipes mysql_remap regex_remap \
		  stale_while_revalidate stats_over_http \
		  memcached_remap

all:
	@for plugin in $(SUBDIRS); do \
		echo "Making $$plugin plugin"; \
		$(MAKE) -C $$plugin || { \
			echo "Unable to build $$plugin."; \
			exit 1; \
		} \
	done

clean:
	@for plugin in $(SUBDIRS); do \
		echo "Cleaning up in $$plugin plugin"; \
		$(MAKE) -C $$plugin clean ; \
	done

remove_distdir = \
  { test ! -d "$(distdir)" \
    || { find "$(distdir)" -type d ! -perm -200 -exec chmod u+w {} ';' \
         && rm -fr "$(distdir)"; }; }

asf-distdir:
	@$(remove_distdir)
	test -d .git && git clone . $(distdir) || svn export . $(distdir)

asf-dist: asf-distdir
	tardir=$(distdir) && $(TAR) | bzip2 -9 -c >$(distdir).tar.bz2
	$(am__remove_distdir)

asf-dist-sign: asf-dist
	md5sum -b $(distdir).tar.bz2 >$(distdir).tar.bz2.md5
	sha1sum -b $(distdir).tar.bz2 >$(distdir).tar.bz2.sha1
	gpg --armor --output $(distdir).tar.bz2.asc  --detach-sig $(distdir).tar.bz2

