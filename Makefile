.PHONY: help build run
.DEFAULT: help

help:
	@echo "make run api_key=<api_key> city=<city>"
	@echo "       run project with arguments <api_key> and <city>"

build:
	

run:
	python xchlup08.py $(api_key) $(city)
