GO ?= go
BINARY := main

.PHONY: all clean
all: $(BINARY)

$(BINARY): main.go
	@version="$$($(GO) version)"; \
	case "$$version" in \
	  *" go1.17."*) ;; \
	  *) echo "warning: the goroutine goid offset was validated with Go 1.17; verify it for $$version" >&2 ;; \
	esac
	$(GO) build -o $@ $<

clean:
	rm -f $(BINARY)
