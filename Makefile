.PHONY: help run
.DEFAULT: help

help:
	@echo "make run api_key=<api_key> city=<city>"
	@echo "       run project with arguments <api_key> and <city>"

run:
	python xchlup08.py $(api_key) $(city)
