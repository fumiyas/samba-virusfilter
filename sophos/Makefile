SOURCE_DIR=	..
SOURCE_BUILD=	$(SOURCE_DIR)/build

## ======================================================================

DIRS=

BUILD_OBJS=		svf-sophos.o
BUILD_VFS=		svf-sophos.so
BUILD_TARGETS=		$(BUILD_OBJS) $(BUILD_VFS)
BUILD_TARGETS_POST=

INSTALL_DIR=		$(SAMBA_VFSLIBDIR)
INSTALL_EXES=		$(BUILD_VFS)

## ======================================================================

include $(SOURCE_BUILD)/Makefile.common

$(BUILD_OBJS): $(SAV_VFS_HEADERS)

$(BUILD_VFS): $(BUILD_OBJS) $(SAV_VFS_OBJS)
	$(SHLD) $(LDSHFLAGS_MODULES) -o $@ $(BUILD_OBJS) $(SAV_VFS_OBJS)

install:: install-exes

