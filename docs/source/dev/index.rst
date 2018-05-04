Developers Guide
################

.. include:: ../../../CONTRIBUTING.rst


.. _testing-label:

Testing
=======

The rastrea2r project implements a regression
test suite that improves developer productivity by identifying capability
regressions early.

Developers implementing fixes or enhancements must ensure that they have
not broken existing functionality. The rastrea2r
project provides some convenience tools so this testing step can be quickly
performed.

Use the Makefile convenience rules to run the tests.

.. code-block:: console

    (venv) $ make test

To run tests verbosely use:

.. code-block:: console

    (venv) $ make test-verbose

Alternatively, you may want to run the tests suite directly. The following
steps assume you are running in a virtual environment in which the
``rastrea2r`` package has been installed. If this is
not the case then you will likely need to set the ``PYTHONPATH`` environment
variable so that the ``rastrea2r`` package can be found.

.. code-block:: console

    (venv) $ cd tests
    (venv) $ python -m unittest

Individual unit tests can be run also.

.. code-block:: console

    (venv) $ python -m test_basic


.. _test-coverage-label:

Coverage
========

The ``coverage`` tool can be run to collect code test coverage metrics.

Use the Makefile convenience rule to run the tests.

.. code-block:: console

    (venv) $ make check-coverage

The test code coverage report can be found `here <../coverage/coverage.html>`_


.. _style-compliance-label:

Code Style
==========

Adopting a consistent code style assists with maintenance.

Use the Makefile convenience rule to check code style compliance.

.. code-block:: console

    (venv) $ make check-style

A separate style fix rule is available to automate fixing minor problems.
More complicated problems will need to be fixed manually.

.. code-block:: console

    (venv) $ make fix-style


.. _annotations-label:

Type Annotations
================

The code base contains type annotations to provide helpful type information
that can improve code maintenance.

Use the Makefile convenience rule to check no issues are reported.

.. code-block:: console

    (venv) $ make check-types


.. _documentation-label:

Documentation
=============

To rebuild this project's documentation, developers should use the Makefile
in the top level directory. It performs a number of steps to create a new
set of `sphinx <http://sphinx-doc.org/>`_ html content.

.. code-block:: console

    (venv) $ make docs

To quickly check consistency of ReStructuredText files use the dummy run which
does not actually generate HTML content.

.. code-block:: console

    (venv) $ make check-docs

To quickly view the HTML rendered docs, start a simple web server and open a
browser to http://127.0.0.1:8000/.

.. code-block:: console

    (venv) $ make serve-docs


.. _release-label:

Release Process
===============

The following steps are used to make a new software release.

The steps assume they are executed from within a development virtual
environment.

- Check that the package version label in ``__init__.py`` is correct.

- Create and push a repo tag to Github. As a convention use the package
  version number (e.g. YY.MM.MICRO) as the tag.

  .. code-block:: console

      $ git checkout master
      $ git tag YY.MM.MICRO -m "A meaningful release tag comment"
      $ git tag  # check release tag is in list
      $ git push --tags origin master

  - This will trigger Github to create a release at:

    ::

        https://github.com/{username}/rastrea2r/releases/{tag}

- Create the release distribution. This project produces an artefact called a
  pure Python wheel. The wheel file will be created in the ``dist`` directory.

  .. code-block:: console

      (venv) $ make dist

- Test the release distribution. This involves creating a virtual environment,
  installing the distribution into it and running project tests against the
  installed distribution. These steps have been captured for convenience in a
  Makefile rule.

  .. code-block:: console

      (venv) $ make dist-test

- Upload the release to PyPI using

  .. code-block:: console

      (venv) $ make dist-upload

  The package should now be available at https://pypi.org/project/rastrea2r/
