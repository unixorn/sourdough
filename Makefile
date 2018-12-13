help:
	@echo '`make docs` to make the documention'
	@echo '`make clean` to clean up'
	@echo '`make wheel` to make a wheel file'
	@echo '`make upload` to upload'
	@echo '`make develop` to do a local developer install'
	@echo '`make test` build a testing container, then run the test suite inside it via docker-compose'

clean:
	python setup.py clean

docs:
	pandoc --from=markdown --to=rst --output=README.rst README.md

upload: docs
	python setup.py sdist upload -r pypi
	python setup.py bdist_wheel upload -r pypi

wheel:
	python setup.py bdist_wheel

develop:
	python setup.py develop

u: upload

container:
	docker-compose build

run_tests:
	docker-compose run --rm sourdough-test /test/sourdough-tester.py

test: container run_tests
t: test
