#!/usr/bin/env python
from os import environ
from os.path import dirname, join
from sys import argv

if __name__ == "__main__":
    environ.setdefault("DJANGO_SETTINGS_MODULE", "sheldon.settings.local")
    environ.setdefault("SHELDON_SECRET_FILE", join(dirname(dirname(__file__)), "secrets"))

    if len(argv) > 1 and not argv[1] in ("migrate", "syncdb"):
        from sheldon.apps.secrets.utils import get_secret
        from django.conf import settings
        settings.SHELDON_SECRET = get_secret()

    from django.core.management import execute_from_command_line

    execute_from_command_line(argv)
