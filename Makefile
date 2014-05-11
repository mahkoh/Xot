all:
	rustc lib.rs

warnings:
	rustc --no-trans lib.rs

.PHONY: warnings all
