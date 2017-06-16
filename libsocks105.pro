TARGET = socks105

TEMPLATE = lib
CONFIG += console
CONFIG += staticlib
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    socks105.c

HEADERS += \
    socks105.h

QMAKE_CFLAGS += -std=c99
