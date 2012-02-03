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
#
TSXS?=$(shell which tsxs)

# you may need to change the path to memcached.h 
export CPPFLAGS+=-Wall $(shell pkg-config --cflags libmemcached)

# you may need to adjust the path
export LDFLAGS += $(shell pkg-config --libs libmemcached)

all:	memcached_remap.cc 
	$(TSXS) -v -C $? -o memcached_remap.so

install: all
	$(TSXS) -i -o memcached_remap.so

clean:
	rm -f *.lo *.so src/*.lo src/*.so
