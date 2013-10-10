TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.c \
    sha2.c \
    secp256k1.c \
    ripemd160.c \
    rand.c \
    hmac.c \
    ecdsa.c \
    bignum.c \
    pbkdf2.c

HEADERS += \
    types.h \
    sha2.h \
    secp256k1.h \
    ripemd160.h \
    rand.h \
    hmac.h \
    ecdsa.h \
    bignum.h \
    pbkdf2.h

