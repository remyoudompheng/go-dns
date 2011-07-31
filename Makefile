include $(GOROOT)/src/Make.inc

TARG=dns
GOFILES=\
	dns.go\
	label.go\
	codes.go\
	packet.go\
	question.go\

include $(GOROOT)/src/Make.pkg
