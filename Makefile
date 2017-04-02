help:
	@echo '`make clean` to clean up'
	@echo '`make develop` to do a local developer install'
	@echo '`make docs` to make the documention'
	@echo '`make upload` to upload'
	@echo '`make wheel` to make a wheel file'

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
