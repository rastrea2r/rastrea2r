# This makefile has been created to help developers perform common actions.
# Most actions assume it is operating in a virtual environment where the
# python command links to the appropriate virtual environment Python.

STYLE_EXCLUDE_LIST := git status --porcelain --ignored | grep "!!" | grep ".py$$" | cut -d " " -f2 | tr "\n" ","
STYLE_MAX_LINE_LENGTH := 160
VENVS_DIR := $(HOME)/.venvs
VENV_DIR := $(VENVS_DIR)/rastrea2r

# Do not remove this block. It is used by the 'help' rule when
# constructing the help output.
# help:
# help: rastrea2r Makefile help
# help:

# help: help                           - display this makefile's help information
.PHONY: help
help:
	@grep "^# help\:" Makefile | grep -v grep | sed 's/\# help\: //' | sed 's/\# help\://'

# help: venv                           - create a virtual environment for development
.PHONY: venv
venv:
	@test -d "$(VENVS_DIR)" || mkdir -p "$(VENVS_DIR)"
	@rm -Rf "$(VENV_DIR)"
	@python2 -m virtualenv "$(VENV_DIR)"
	@/bin/bash -c "source $(VENV_DIR)/bin/activate && pip install pip --upgrade && pip install -r requirements.dev.txt && pip install -e ."
	@echo "Enter virtual environment using:\n\n\t$ source $(VENV_DIR)/bin/activate\n"


# help: clean                          - clean all files using .gitignore rules
.PHONY: clean
clean:
	@git clean -X -f -d


# help: scrub                          - clean all files, even untracked files
.PHONY: scrub
scrub:
	git clean -x -f -d


# help: test                           - run tests
.PHONY: test
test:
	@python -m unittest discover -s tests


# help: test-verbose                   - run tests [verbosely]
.PHONY: test-verbose
test-verbose:
	@python -m unittest discover -s tests -v


# help: check-coverage                 - perform test coverage checks
.PHONY: check-coverage
check-coverage:
	@coverage run -m unittest discover -s tests
	@# produce html coverage report on modules
	@coverage html -d docs/source/coverage --include="src/rastrea2r/*"
	@# rename coverage html file for latter use with documentation
	@cd docs/source/coverage; mv index.html coverage.html


# help: check-style                    - perform pep8 check
.PHONY: check-style
check-style:
	@pycodestyle --exclude=.git,docs,$(shell $(STYLE_EXCLUDE_LIST)) --ignore=E309,E402 --max-line-length=$(STYLE_MAX_LINE_LENGTH) src/rastrea2r tests


# help: fix-style                      - perform check with autopep8 fixes
.PHONY: fix-style
fix-style:
	@# If there are no files to fix then autopep8 typically returns an error
	@# because it did not get passed any files to work on. Use xargs -r to
	@# avoid this problem.
	@pycodestyle --exclude=.git,docs,$(shell $(STYLE_EXCLUDE_LIST)) --ignore=E309,E402 --max-line-length=$(STYLE_MAX_LINE_LENGTH) src/rastrea2r tests -q  | xargs autopep8 -i --max-line-length=$(STYLE_MAX_LINE_LENGTH)


# help: docs                           - generate project documentation
.PHONY: check-coverage
docs: check-coverage
	@cd docs; rm -rf source/api/rastrea2r*.rst source/api/modules.rst build/*
	@cd docs; make html
	@# Copy coverage output into docs build tree
	@cd docs; cp -R source/coverage build/html/.


# help: check-docs                     - quick check docs consistency
.PHONY: check-docs
check-docs:
	@cd docs; make dummy


# help: serve-docs                     - serve project html documentation
.PHONY: serve-docs
serve-docs:
	@cd docs/build; python -m http.server --bind 127.0.0.1


# help: dist                           - create a wheel distribution package
.PHONY: dist
dist:
	@python setup.py bdist_wheel


# help: dist-test                      - test a whell distribution package
.PHONY: dist-test
dist-test: dist
	@cd dist && ../tests/test-dist.bash ./rastrea2r-*-py2-none-any.whl


# help: dist-upload                    - upload a wheel distribution package
.PHONY: dist-upload
dist-upload:
	@twine upload dist/rastrea2r-*-py2-none-any.whl


# Keep these lines at the end of the file to retain nice help
# output formatting.
# help:
