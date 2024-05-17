all:
	(cd src; make all)

clean:
	(cd src; make clean)

help:
	(cd src; make help)

.PHONY: all clean help