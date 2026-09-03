#!/usr/bin/env python
"""Django's command-line utility for the demo OP.

Run::

    cd examples/django-op && python manage.py runserver 5000
"""

import os
import sys


def main():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "opsite.settings")
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
