SOURCE_DIR=	..
SOURCE_BUILD=	$(SOURCE_DIR)/build

## ======================================================================

MAKE_DIRS=

BUILD_OBJS=		virusfilter-clamav.o virusfilter-fsav.o virusfilter-sophos.o
BUILD_VFS=		virusfilter-clamav.so virusfilter-fsav.so virusfilter-sophos.so
BUILD_TARGETS=		$(BUILD_OBJS) $(BUILD_VFS)
BUILD_TARGETS_POST=

INSTALL_CMD_DIR=	$(SAMBA_VFSLIBDIR)
INSTALL_CMDS=		$(BUILD_VFS)

## ======================================================================

include $(SOURCE_BUILD)/Makefile.common

$(BUILD_OBJS):: $(VIRUSFILTER_VFS_HEADERS)

$(BUILD_VFS):: $(BUILD_OBJS) $(VIRUSFILTER_VFS_OBJS)
	$(SHLD) $(LDSHFLAGS_MODULES) -o $@ $(BUILD_OBJS) $(VIRUSFILTER_VFS_OBJS)

install:: install-cmds

