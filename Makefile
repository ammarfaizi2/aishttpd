# SPDX-License-Identifier: GPL-2.0-only
CC := gcc
CXX := g++
CFLAGS := -Wall -Wextra -O2 -ggdb3 -D_GNU_SOURCE
LDFLAGS := -O2 -ggdb3
DEPFLAGS := -MMD -MP
AISHTTPD_SOURCES := \
	src/main.c \
	src/http.c \
	src/tcp.c
AISHTTPD_OBJECTS := $(AISHTTPD_SOURCES:.c=.o)
AISHTTPD_DEPS := $(AISHTTPD_SOURCES:.c=.d)

ifeq ($(SANITIZE),1)
    CFLAGS += -fsanitize=address -fsanitize=undefined
    LDFLAGS += -fsanitize=address -fsanitize=undefined
endif

all: aishttpd

aishttpd: $(AISHTTPD_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^

-include $(AISHTTPD_DEPS)

%.o: %.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

clean:
	rm -f aishttpd $(AISHTTPD_OBJECTS) $(AISHTTPD_DEPS)

.PHONY: all clean
