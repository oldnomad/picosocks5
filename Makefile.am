SUBDIRS = src tests
nobase_dist_doc_DATA = README.md

if LCOV_PRESENT
.PHONY: coverage

clean-local: clean-coverage

coverage: coverage/index.html

coverage/index.html: coverage.info
	$(GENHTML) coverage.info --output-directory coverage/

coverage.info: check
	$(LCOV) --capture --directory src/ --output $@

clean-coverage:
	-rm -rf coverage/ coverage.info
endif
