DESTDIR ?= html
PANDOC  ?= pandoc

SOURCE_BASE_URL ?= https://github.com/abuild-project/spawn-manager/blob/master

PANDOC_OPTS = \
	--from=gfm \
	--to=html5 \
	--standalone \
	--toc \
	--css=styles.css

HTML_DOCUMENTS = \
	$(DESTDIR)/index.html \
	$(DESTDIR)/CHANGELOG.html \
	$(DESTDIR)/WORK_QUEUE.html \
	$(DESTDIR)/protocol-v1.html \
	$(DESTDIR)/lifecycle-v1.html \
	$(DESTDIR)/styles.css

all: $(HTML_DOCUMENTS)

$(DESTDIR):
	mkdir -p $@

$(DESTDIR)/index.html: ../README.md Makefile | $(DESTDIR)
	$(PANDOC) $(PANDOC_OPTS) --metadata pagetitle="Ada Spawn Manager" \
		-o $@.tmp $<
	sed \
		-e 's|href="CHANGELOG.md"|href="CHANGELOG.html"|g' \
		-e 's|href="WORK_QUEUE.md"|href="WORK_QUEUE.html"|g' \
		-e 's|href="doc/protocol-v1.md"|href="protocol-v1.html"|g' \
		-e 's|href="doc/lifecycle-v1.md"|href="lifecycle-v1.html"|g' \
		-e 's|href="src/spawn-pool.ads"|href="$(SOURCE_BASE_URL)/src/spawn-pool.ads"|g' \
		-e 's|href="AUTHORS"|href="$(SOURCE_BASE_URL)/AUTHORS"|g' \
		-e 's|href="COPYING"|href="$(SOURCE_BASE_URL)/COPYING"|g' \
		$@.tmp > $@
	rm -f $@.tmp

$(DESTDIR)/CHANGELOG.html: ../CHANGELOG.md Makefile | $(DESTDIR)
	$(PANDOC) $(PANDOC_OPTS) --metadata pagetitle="Spawn Manager changelog" \
		-o $@ $<

$(DESTDIR)/WORK_QUEUE.html: ../WORK_QUEUE.md Makefile | $(DESTDIR)
	$(PANDOC) $(PANDOC_OPTS) --metadata pagetitle="Spawn Manager work queue" \
		-o $@ $<

$(DESTDIR)/protocol-v1.html: protocol-v1.md Makefile | $(DESTDIR)
	$(PANDOC) $(PANDOC_OPTS) --metadata pagetitle="Protocol version 1" \
		-o $@.tmp $<
	sed \
		-e 's|href="../src/spawn-protocol.ads"|href="$(SOURCE_BASE_URL)/src/spawn-protocol.ads"|g' \
		-e 's|href="../README.md#anet-boundary"|href="index.html#anet-boundary"|g' \
		$@.tmp > $@
	rm -f $@.tmp

$(DESTDIR)/lifecycle-v1.html: lifecycle-v1.md Makefile | $(DESTDIR)
	$(PANDOC) $(PANDOC_OPTS) --metadata pagetitle="Lifecycle version 1" \
		-o $@.tmp $<
	sed \
		-e 's|href="protocol-v1.md|href="protocol-v1.html|g' \
		-e 's|href="../src/spawn-pool.ads"|href="$(SOURCE_BASE_URL)/src/spawn-pool.ads"|g' \
		$@.tmp > $@
	rm -f $@.tmp

$(DESTDIR)/styles.css: css/styles.css Makefile | $(DESTDIR)
	cp $< $@

clean:
	@rm -rf $(DESTDIR)

.PHONY: all clean
