SOURCE_DIR=	..
SOURCE_BUILD=	$(SOURCE_DIR)/build

## ======================================================================

MAKE_DIRS=

BUILD_TARGETS=		$(TEST_DIRS) $(TEST_LIB_PACKAGE)

SUBST_ARGS=		TEST_DIR="$(TEST_DIR)" \
			TEST_BIN_DIR="$(TEST_DIR)/$(TEST_BIN_DIR)" \
			TEST_LIB_DIR="$(TEST_DIR)/$(TEST_LIB_DIR)" \
			TEST_TMP_DIR="$(TEST_DIR)/$(TEST_TMP_DIR)" \
			TEST_LOG_DIR="$(TEST_DIR)/$(TEST_LOG_DIR)" \
			TEST_SAMBA_BIN_DIR="$(SAMBA_SOURCE_DIR)/bin" \
			TEST_SAMBA_SBIN_DIR="$(SAMBA_SOURCE_DIR)/bin" \
			TEST_SAMBA_LIB_DIR="$(SAMBA_SOURCE_DIR)/bin" \

#TEST_USER=		`id |sed 's/).*//;s/.*(//'`
#TEST_PASSWORD=		test

TEST_DIR=		`pwd`
TEST_DIRS=		$(TEST_TMP_DIR) $(TEST_LOG_DIR)

TEST_BIN_DIR=		bin
TEST_LIB_DIR=		lib
TEST_TMP_DIR=		tmp
TEST_LOG_DIR=		log

TEST_LIB_PACKAGE=	$(TEST_LIB_DIR)/package.ksh

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

#$(SMB_GLOBAL_CONF_FILE): $(SMB_GLOBAL_CONF_FILE).tmpl
#	@echo "Generating $@ ..."
#	@$(SUBST) <$(SMB_GLOBAL_CONF_FILE).tmpl >$@.tmp
#	@mv $@.tmp $@

$(SMB_AUTH_FILE):
	@echo "Generating $@ ..."
	@(umask 0077; touch $@.tmp)
	@echo "username=$(TEST_USER)" >$@.tmp
	@echo "password=$(TEST_PASSWORD)" >>$@.tmp
	@mv $@.tmp $@

