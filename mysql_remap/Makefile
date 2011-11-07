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


# you may need to change the path to mysql.h 
export CPPFLAGS+=-I /opt/local/include/mysql5/ -ggdb -O0

# you may need to adjust the path
export LDFLAGS +=-l mysqlclient_r -L/opt/local/lib/mysql5/mysql

all:	mysql_remap.cc lib/dictionary.c lib/iniparser.c 
	tsxs -C $? -o mysql_remap.so

install: all
	tsxs -i -o mysql_remap.so

clean:
	rm -f *.lo *.so src/*.lo src/*.so
