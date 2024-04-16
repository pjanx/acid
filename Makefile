.POSIX:
.SUFFIXES:

version = dev
outputs = acid acid.1
all: $(outputs)

acid: acid.go
	go build -ldflags "-X 'main.projectVersion=$(version)'" -o $@
acid.1: acid.adoc
	asciidoctor -b manpage -a release-version=$(version) -o $@ acid.adoc
test: all
	go test
clean:
	rm -f $(outputs)
