TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.c \
    socks105.c

HEADERS += \
    socks105.h

QMAKE_CFLAGS += -std=c99
