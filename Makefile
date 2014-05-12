all:
	rustc lib.rs

warnings:
	rustc --no-trans lib.rs

docs:
	rm -rf doc
	rustdoc lib.rs

devdocs:
	rm -rf doc
	rustdoc --no-defaults --passes "collapse-docs" --passes "unindent-comments" lib.rs

clean:
	rm -f libxot-*.rlib

.PHONY: warnings all
