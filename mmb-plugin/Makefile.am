# Copyright (c) 2018 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# modfied by Korian Edeline

AUTOMAKE_OPTIONS = foreign subdir-objects

AM_CFLAGS = -Wall -I${top_srcdir} -I${top_builddir}
AM_LDFLAGS = -module -shared -avoid-version
AM_LIBTOOLFLAGS = --quiet

BUILT_SOURCES =
vppplugins_LTLIBRARIES =
noinst_HEADERS =
ACLOCAL_AMFLAGS = -I m4

vpppluginsdir = ${libdir}/vpp_plugins

include mmb.am

# Remove *.la files
install-data-hook:
	@(cd $(vpppluginsdir) && $(RM) $(vppplugins_LTLIBRARIES))

CLEANFILES = $(BUILT_SOURCES)
