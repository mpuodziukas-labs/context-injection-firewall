Contributing
============

Thanks for helping. Please read this page before opening a pull request.

Setting up
----------

1. Fork the repository and clone your fork.
2. Create a virtual environment and run ``pip install -e .[dev]``.
3. Run ``pytest -q``. All tests must pass before you push.

Style
-----

* Format with the project formatter. Do not reformat unrelated lines.
* Keep functions short. Prefer a clear name over a comment.
* Add a test for every bug you fix.

Commit messages
---------------

Use the form ``type: what``, for example ``fix: handle empty input``. Keep the first line under 72 characters.

Review
------

A maintainer will reply within a week. If the previous review comments were not addressed, the pull request may be closed.
