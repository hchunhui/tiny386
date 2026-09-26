WAYLAND_SCANNER   := $(shell pkg-config --variable=wayland_scanner wayland-scanner)
PROTOCOLS_DIR     := $(shell pkg-config --variable=pkgdatadir wayland-protocols)
WAYLAND_CORE_DIR  := $(shell pkg-config --variable=pkgdatadir wayland-client)

ifeq ($(WAYLAND_CORE_DIR),)
    WAYLAND_CORE_DIR := /usr/share/wayland
endif

XML_WAYLAND           := $(WAYLAND_CORE_DIR)/wayland.xml
XML_XDG_SHELL         := $(PROTOCOLS_DIR)/stable/xdg-shell/xdg-shell.xml
XML_SHORTCUTS_INHIBIT := $(PROTOCOLS_DIR)/unstable/keyboard-shortcuts-inhibit/keyboard-shortcuts-inhibit-unstable-v1.xml
XML_POINTER_CONSTR    := $(PROTOCOLS_DIR)/unstable/pointer-constraints/pointer-constraints-unstable-v1.xml
XML_RELATIVE_POINTER  := $(PROTOCOLS_DIR)/unstable/relative-pointer/relative-pointer-unstable-v1.xml

GEN_SOURCES := wayland-protocol.c \
               xdg-shell-client-protocol.c \
               keyboard-shortcuts-inhibit.c \
               pointer-constraints.c \
               relative-pointer.c

GEN_HEADERS := xdg-shell-client-protocol.h \
               keyboard-shortcuts-inhibit.h \
               pointer-constraints.h \
               relative-pointer.h

all: $(GEN_SOURCES) $(GEN_HEADERS)

wayland-protocol.c: $(XML_WAYLAND)
	$(WAYLAND_SCANNER) private-code $< $@

xdg-shell-client-protocol.h: $(XML_XDG_SHELL)
	$(WAYLAND_SCANNER) client-header $< $@

xdg-shell-client-protocol.c: $(XML_XDG_SHELL)
	$(WAYLAND_SCANNER) private-code $< $@

keyboard-shortcuts-inhibit.h: $(XML_SHORTCUTS_INHIBIT)
	$(WAYLAND_SCANNER) client-header $< $@

keyboard-shortcuts-inhibit.c: $(XML_SHORTCUTS_INHIBIT)
	$(WAYLAND_SCANNER) private-code $< $@

pointer-constraints.h: $(XML_POINTER_CONSTR)
	$(WAYLAND_SCANNER) client-header $< $@

pointer-constraints.c: $(XML_POINTER_CONSTR)
	$(WAYLAND_SCANNER) private-code $< $@

relative-pointer.h: $(XML_RELATIVE_POINTER)
	$(WAYLAND_SCANNER) client-header $< $@

relative-pointer.c: $(XML_RELATIVE_POINTER)
	$(WAYLAND_SCANNER) private-code $< $@

clean:
	rm -f $(GEN_SOURCES) $(GEN_HEADERS)

.PHONY: all clean
