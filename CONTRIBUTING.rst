Contributing Guide
==================

Contributions are welcome and greatly appreciated!


.. _contributing-workflow-label:

Workflow
--------

A bug-fix or enhancement is delivered using a pull request. A good pull request
should cover one bug-fix or enhancement feature. This ensures the change set is
easier to review and less likely to need major re-work or even be rejected.

The workflow that developers typically use to fix a bug or add enhancements
is as follows.

* Fork the ``rastrea2r`` repo into your account.

* Obtain the source by cloning it onto your development machine.

  .. code-block:: console

      $ git clone git@github.com:your_name_here/rastrea2r.git
      $ cd rastrea2r

* Create a branch for local development:

  .. code-block:: console

      $ git checkout -b name-of-your-bugfix-or-feature

  Now you can make your changes locally.

.. note::  Below instructions assumes that you are developing on a Mac or Unix system. If you are on Windows machine,
           then please note that you have to have the MakeFile support is installed. One way to install the make files is
           by using the mingw. Please refer to: http://www.mingw.org/wiki/getting_started for more details

* Familiarize yourself with the developer convenience rules in the Makefile.

  .. code-block:: console

      $ make help

* Create and activate a Python virtual environment for local development.

  .. code-block:: console

      $ make venv
      $ source path/to/<venv-name>/bin/activate
      (venv) $

  The rule creates the virtual environment outside the project directory so
  that it never accidentally gets added to the change set.

  .. note::

      (venv) is used to indicate when the commands should be run within the
      virtual environment containing the development dependencies.

* Develop fix or enhancement:

  * Make a fix or enhancement (e.g. modify a class, method, function, module,
    etc).

  * Update an existing unit test or create a new unit test module to verify
    the change works as expected.

  * Run the test suite.

    .. code-block:: console

        (venv) $ make test

    See the :ref:`testing-label` section for more information on testing.

  * Check code coverage of the area of code being modified.

    .. code-block:: console

        (venv) $ make check-coverage

    Review the output produced in ``docs/source/coverage/coverage.html``. Add
    additional test steps, where practical, to improve coverage.

  * The change should be style compliant. Perform style check.

    .. code-block:: console

        (venv) $ make check-style

    See the :ref:`style-compliance-label` section for more information.

  * The change should include type annotations where appropriate.
    Perform type annotations check.

    .. code-block:: console

        (venv) $ make check-types

    See the :ref:`annotations-label` section for more information.

  * Fix any errors or regressions.

* The docs and the change log should be updated for anything but trivial bug
  fixes. Perform docs check.

    .. code-block:: console

        (venv) $ make docs

  See the :ref:`documentation-label` section for more information.

* Commit and push changes to your fork.

  .. code-block:: console

      $ git add .
      $ git commit -m "A detailed description of the changes."
      $ git push origin name-of-your-bugfix-or-feature

  A pull request should preferably only have one commit upon the current
  master HEAD, (via rebases and squash).

* Submit a pull request through the service website (e.g. Github, Gitlab).

* Check automated continuous integration steps all pass. Fix any problems
  if necessary and update the pull request.
