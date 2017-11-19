PROG		?= low-entropy-eschalot

PREFIX		?= /usr/local
BINDIR		?= ${PREFIX}/bin

LIBS		+= -lpthread -lssl -lcrypto

WARNINGS	+= -Wall -W -Wunused -pedantic -Wpointer-arith \
		-Wreturn-type -Wstrict-prototypes \
		-Wmissing-prototypes -Wshadow -Wcast-qual -Wextra

#CFLAGS		+= -std=c99
CFLAGS		+= -O2
CFLAGS		+= -fPIC
CFLAGS		+= -finline-functions
#CFLAGS		+= -fomit-frame-pointer
#CFLAGS		+= -m64
#CFLAGS		+= -mtune=native -march=native
#CFLAGS		+= -g


ifneq ($(OS),Windows_NT)
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Darwin)
		LIBS += -L/usr/local/opt/openssl/lib
		CFLAGS += -I/usr/local/opt/openssl/include
    endif
endif

CC		?= clang++
INSTALL		?= install -c -o root -g bin -m 755
RM		?= /bin/rm -f

all:		${PROG}

${PROG}:	${PROG}.c Makefile
		${CC} ${CFLAGS} ${WARNINGS} -o $@ ${PROG}.c ${LIBS}



clean:
		${RM} ${PROG} *.o *.p *.d *.s *.S *~ *.core .depend

# Simple procedure to speed up basic testing on multiple platforms
WF1		= top150adjectives.txt
WF2		= top400nouns.txt
WF3		= top1000.txt
WLIST		= wordlist.txt
RESULTS		= results.txt

test:		all
		./${PROG2} 8-16 ${WF1} 3-16 ${WF2} 3-16 ${WF3} 3-16 > ${WLIST}
		./${PROG1} -vct4 -f ${WLIST} >> ${RESULTS}

cleantest:
		${RM} ${WLIST} ${RESULTS}

cleanall:	clean cleantest

