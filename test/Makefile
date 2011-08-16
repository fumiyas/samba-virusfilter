SOURCE_DIR=	..
SOURCE_BUILD=	$(SOURCE_DIR)/build

## ======================================================================

BUILD_TARGETS=		$(TEST_DIRS) $(TEST_LIB_PACKAGE) \
			etc/clamd.conf.test \
			etc/savdid.conf.test \
			bin/clamd-svconf.cmd \
			bin/savdid-svconf.cmd \

SUBST_ARGS=		TEST_DIR="$(TEST_DIR)" \
			TEST_SYSCONF_DIR="$(PWD)/etc" \
			TEST_BIN_DIR="$(PWD)/bin" \
			TEST_LIB_DIR="$(PWD)/lib" \
			TEST_TMP_DIR="$(PWD)/tmp" \
			TEST_LOG_DIR="$(PWD)/log" \
			TEST_SAMBA_BIN_DIR="$(SAMBA_SOURCE_DIR)/bin" \
			TEST_SAMBA_SBIN_DIR="$(SAMBA_SOURCE_DIR)/bin" \
			TEST_SAMBA_LIB_DIR="$(SAMBA_SOURCE_DIR)/bin" \

#TEST_USER=		`id |sed 's/).*//;s/.*(//'`
#TEST_PASSWORD=		test

TEST_DIR=		$(PWD)
TEST_DIRS=		tmp log

TEST_LIB_PACKAGE=	lib/package.ksh

#SMB_GLOBAL_CONF_FILE=	tmp/smb.global.conf
#SMB_AUTH_FILE=		tmp/smb.auth

## ======================================================================

include $(SOURCE_BUILD)/Makefile.common

clean::
	rm -rf $(TEST_DIRS)

$(TEST_DIRS)::
	@echo "Creating $@ ..."
	@mkdir -p -m 0755 $@

$(TEST_LIB_PACKAGE):: $(TEST_LIB_PACKAGE).tmpl
	@echo "Generating $@ ..."
	@$(SUBST) <$(TEST_LIB_PACKAGE).tmpl >$@

