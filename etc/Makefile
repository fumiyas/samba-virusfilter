SOURCE_DIR=	..
SOURCE_BUILD=	$(SOURCE_DIR)/build

## ======================================================================

BUILD_TARGETS=		smb.svf-clamav.conf.example \
			smb.svf-fsav.conf.example \
			smb.svf-sophos.conf.example

INSTALL_DIR=		$(SAMBA_CONFIGDIR)
INSTALL_FILES=		$(BUILD_TARGETS)

## ======================================================================

include $(SOURCE_BUILD)/Makefile.common

install:: install-files

