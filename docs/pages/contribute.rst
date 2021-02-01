##########
Contribute
##########

If you want to contribute to any of the nuts foundation projects or to this documentation, please fork the correct project from `Github <https://github.com/nuts-foundation>`_ and create a pull-request.

***************************
Documentation contributions
***************************

Documentation is written in Restructured Text. A CheatSheet can be found `here <https://thomas-cokelaer.info/tutorials/sphinx/rest_syntax.html>`_.

You can test your documentation by installing the required components.

****************************
Documentation initialisation
****************************

When starting a new project, the documentation can be initialised using::

    sphinx-quickstart docs

This will start the interactive setup of sphinx with a document root at *docs*. For Nuts projects we use that specific directory for documentation in a code project. You might have noticed that the *nuts-documentation* repo uses the root directory as documentation root.

Most defaults will do, although we use intersphinx to go back-and-forth between the different sub-projects.
