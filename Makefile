CFLAGS?=	-g -O2 -Wall -Wextra -pedantic
LIBS=

#CFLAGS+=	-DNDEBUG
#CFLAGS+=	-DHAVE_FDATASYNC

UNAME:=		$(shell uname)
ifeq ($(UNAME), Darwin)
CFLAGS+=	-mmacosx-version-min=10.5
endif
ifeq ($(UNAME), Linux)
LIBS+=		-lbsd
endif

# XXX conditionalize PKG_CONFIG_PATH here:
PC_CFLAGS:=	$(shell PKG_CONFIG_PATH=/usr/local/lib/pkgconfig pkg-config --cflags fuse openssl)
PC_LIBS:=	$(shell PKG_CONFIG_PATH=/usr/local/lib/pkgconfig pkg-config --libs fuse openssl)
CFLAGS+=	-std=c99 $(PC_CFLAGS)
LIBS+=		$(PC_LIBS)

TARGET=		rosefs
TARGETVER=	0

# debugging
BACKEND:=	$(HOME)/test.rosefs
MNT:=		$(HOME)/mnt

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(LIBS) -o $(TARGET) $(TARGET).c

clean:
	rm -rf *~ *.o $(TARGET).dSYM $(TARGET)

install:
	install -o 0 -g 0 -m 0555 $(TARGET) $(PREFIX)/bin/$(TARGET)$(TARGETVER)
	ln -sf $(TARGET)$(TARGETVER) $(PREFIX)/bin/$(TARGET)

mount:
	./$(TARGET) $(BACKEND) $(MNT)

debug:
	./$(TARGET) $(BACKEND) -d $(MNT)

umount:
	umount $(MNT)

.PHONY: all clean install mount umount debug

