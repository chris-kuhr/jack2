XDP_TARGETS  := xdp_avb_kern
USER_TARGETS := jackd_listener
LOADER_TARGETS := loader

LLC = llc
CLANG = clang
CC = gcc


MRPCLIENT_DIR = ../common
MRPLISTENER_OBJS = listener_mrp_client.o
MRPLISTENER_TARGETS = $(addprefix $(MRPCLIENT_DIR)/,$(MRPLISTENER_OBJS))


DAEMONS_DIR = ../../daemons

XDP_C = ${XDP_TARGETS:=.c}
XDP_OBJ = ${XDP_C:.c=.o}
USER_C := ${USER_TARGETS:=.c}
USER_OBJ := ${USER_C:.c=.o}

# Expect this is defined by including Makefile, but define if not
COMMON_DIR = ./common
LIBBPF_DIR = ./libbpf/src

OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a
# Extend if including Makefile already added some
COMMON_OBJS += $(COMMON_DIR)/common_params.o $(COMMON_DIR)/common_user_bpf_xdp.o
# Create expansions for dependencies
COMMON_H := ${COMMON_OBJS:.o=.h}
# For build dependency on this file, if it gets updated
COMMON_MK = $(COMMON_DIR)/common.mk

# BPF-prog kern and userspace shares struct via header file:
KERN_USER_H = common_kern_user.h

OPT = -O2 -g
WARN = -Wall -Wextra -Wno-parentheses
CFLAGS_BPF = -I$(LIBBPF_DIR)/build/usr/include/ -g
# Extra include for Ubuntu issue #44
CFLAGS_BPF += -I/usr/include/x86_64-linux-gnu
CFLAGS_BPF += -I./headers/
CFLAGS = $(OPT) $(WARN) $(CFLAGS_BPF)-std=gnu99
LDFLAGS = -L$(LIBBPF_DIR)
CPPFLAGS = -I$(DAEMONS_DIR)/mrpd -I$(MRPCLIENT_DIR) -I$(DAEMONS_DIR)/common
LIBS = -l:libbpf.a -lelf -ljack -lpthread


.PHONY: clean $(LOADER_TARGETS) $(XDP_OBJ)

all: $(USER_TARGETS) $(XDP_OBJ) $(LOADER_TARGETS) 

$(MRPCLIENT_DIR)/%.o: $(MRPCLIENT_DIR)/%.c $(MRPCLIENT_DIR)/%.h
	make -C $(MRPCLIENT_DIR) $@

loader:
	make -C $(LOADER_TARGETS)


# Create dependency: detect if C-file change and touch H-file, to trigger
# target $(COMMON_OBJS)
$(COMMON_H): %.h: %.c
	touch $@

# Detect if any of common obj changed and create dependency on .h-files
$(COMMON_OBJS): %.o: %.h
	make -C $(COMMON_DIR)


#%.o: %.c $(OBJECT_LIBBPF) Makefile $(COMMON_MK) $(COMMON_OBJS) $(KERN_USER_H)  

$(USER_TARGETS): $(MRPLISTENER_TARGETS) $(LOADER_TARGETS) $(XDP_OBJ)
	$(CC) -Wall $(CFLAGS) $(LDFLAGS) $(CPPFLAGS) -o $@ $(USER_TARGETS).c  avb_sockets.c  $(MRPLISTENER_TARGETS) $(COMMON_OBJS) $(LIBS) 

	 
	 
$(OBJECT_LIBBPF):
	@if [ ! -d $(LIBBPF_DIR) ]; then \
		echo "Error: Need libbpf submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBBPF_DIR) && $(MAKE) all; \
		mkdir -p build; DESTDIR=build $(MAKE) install_headers; \
	fi
	

$(XDP_OBJ): %.o: %.c  Makefile $(COMMON_MK)
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(CFLAGS_BPF) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

	
clean:
	make -C $(LOADER_TARGETS) clean
	$(RM) $(USER_TARGETS)
	$(RM) `find . -name "*~" -o -name "*.[oa]" -o -name "\#*\#" -o -name TAGS -o -name core -o -name "*.orig"`
