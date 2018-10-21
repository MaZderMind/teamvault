import getpass
import logging
from pprint import pformat

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from pykeepass import PyKeePass

from ...models import Secret

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Import KeePass .kdbx-File'

    def add_arguments(self, parser):
        parser.add_argument('keepass-file', type=str, help="Path of the .kdbx-File to Import")
        parser.add_argument('--dry-run', '-n', action='store_true',
                            help="Only print which items would be Imported, do not actually import anything")
        parser.add_argument('--as-user', type=str, help="Username to use as creator and owner of the new secrets",
                            default="admin")
        parser.add_argument('--keyfile', type=str, help="Path of the Key-File to open the .kdbx-File")
        parser.add_argument('--exclude', type=str, nargs='+', default=[],
                            help="Entries or Groups to exclude. ie --exclude Trash --exclude Super/Secret, "
                                 "can be specified multiple times")
        parser.add_argument('--naming-convention', type=str, default='{title} ({path})',
                            help="Format-String used to format Title and Group into a single Secret-Title\n"
                                 "Available Formats: {title}, {path}, {group}")

    def handle(self, *args, **options):
        logger.debug("import_keepass called with options: %s", pformat(options))
        master_password = self.get_master_password()

        keepass_file = PyKeePass(options['keepass-file'], master_password, options.get('keyfile', None))
        user = next(iter(User.objects.filter(username=options['as_user'])), None)
        if user is None:
            self.stderr.write(self.style.ERROR(
                "User '%s' was not found, select another user with the --as-user option"))
            return False

        for entry in keepass_file.entries:
            if self.is_excluded(entry, options['exclude']):
                continue

            secret_title = options['naming_convention'].format(**{
                'title': entry.title,
                'group': entry.parentgroup.name,
                'path': entry.parentgroup.path,
            })
            secret = Secret(
                name=secret_title,
                url=entry.url,
                username=entry.username,
                description=entry.notes,
                created_by=user
            )
            secret.save()

            secret.allowed_users.set([user])
            secret.save()

            secret.set_data(user, entry.password, skip_access_check=True)

            self.stdout.write(self.style.SUCCESS("imported %s" % secret_title))

    def is_excluded(self, entry, excludes):
        path = entry.parentgroup.path + "/" + entry.title
        for exclude in excludes:
            logger.debug("testing path: %s against exclude %s", path, exclude)

            if path.startswith(exclude):
                logger.info("'%s' is excluded by '%s'", path, exclude)
                return True

        return False

    def get_master_password(self):
        master_password = getpass.getpass('KeePass Master-Password: ')
        if master_password == "":
            master_password = None
        return master_password
