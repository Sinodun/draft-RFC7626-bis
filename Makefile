# Draft Makefile. You will need:
# - mmark (https://github.com/miekg/mmark)
# - xml2rfc (https://xml2rfc.tools.ietf.org/)
# - unoconv (https://github.com/dagwieers/unoconv)

DRAFT=draft-ietf-dprive-rfc7626-bis
VERSION=08

OUTDIR=adopted-draft-$(VERSION)

XML=$(OUTDIR)/$(DRAFT).xml
HTML=$(OUTDIR)/$(DRAFT)-$(VERSION).html
TXT=$(OUTDIR)/$(DRAFT)-$(VERSION).txt
OUTDIREXISTS=$(OUTDIR)/.f

.PHONY: clean

all: $(HTML) $(TXT) $(GRAPHICS)

$(OUTDIREXISTS): ; mkdir -p $(OUTDIR); touch $@

$(XML): $(DRAFT).md $(OUTDIREXISTS); mmark -xml2 -page $< $@

$(HTML): $(XML) ; xml2rfc --html --v2 -o $@ $<
$(TXT): $(XML) ; xml2rfc --text --v2 -o $@ $<



clean: ; rm $(XML) $(HTML) $(TXT) 
