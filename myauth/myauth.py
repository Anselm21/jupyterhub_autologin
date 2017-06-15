from jupyterhub.auth import Authenticator
from jupyterhub.utils import url_path_join
from traitlets import Bool, Set, default, observe
from jupyterhub.traitlets import Command
import sys
from shutil import which
from grp import getgrnam
from subprocess import Popen, PIPE, STDOUT
import pipes
import pwd
from tornado import gen
from jupyterhub.handlers import BaseHandler


class MyLoginHandler(BaseHandler):
    """Get username from auto_login_username.txt file and authenticate that user"""

    def get(self):
        with open("auto_login_username.txt", "r") as file:
            username = file.read().replace('\n', '')
        user = self.user_from_username(username)
        self.set_login_cookie(user)
        self.redirect(url_path_join(self.hub.server.base_url, 'home'))


class MyAuthenticator(Authenticator):
    """CLass overrides default Authenticator to modify /login hook"""

    def login_url(self, base_url):

        return url_path_join(base_url, 'login')

    def get_handlers(self, app):

        return [
            ('/login', MyLoginHandler),
        ]

    pass


class MyLocalAuthenticator(MyAuthenticator):
    """Default LocalAuthenticator"""

    create_system_users = Bool(False,
                               help="""
        If set to True, will attempt to create local system users if they do not exist already.

        Supports Linux and BSD variants only.
        """
                               ).tag(config=True)

    add_user_cmd = Command(
        help="""
        The command to use for creating users as a list of strings

        For each element in the list, the string USERNAME will be replaced with
        the user's username. The username will also be appended as the final argument.

        For Linux, the default value is:

            ['adduser', '-q', '--gecos', '""', '--disabled-password']

        To specify a custom home directory, set this to:

            ['adduser', '-q', '--gecos', '""', '--home', '/customhome/USERNAME', '--disabled-password']

        This will run the command:

            adduser -q --gecos "" --home /customhome/river --disabled-password river

        when the user 'river' is created.
        """
    ).tag(config=True)

    @default('add_user_cmd')
    def _add_user_cmd_default(self):
        """Guess the most likely-to-work adduser command for each platform"""
        if sys.platform == 'darwin':
            raise ValueError("I don't know how to create users on OS X")
        elif which('pw'):
            # Probably BSD
            return ['pw', 'useradd', '-m']
        else:
            # This appears to be the Linux non-interactive adduser command:
            return ['adduser', '-q', '--gecos', '""', '--disabled-password']

    group_whitelist = Set(
        help="""
        Whitelist all users from this UNIX group.

        This makes the username whitelist ineffective.
        """
    ).tag(config=True)

    @observe('group_whitelist')
    def _group_whitelist_changed(self, change):
        """
        Log a warning if both group_whitelist and user whitelist are set.
        """
        if self.whitelist:
            self.log.warning(
                "Ignoring username whitelist because group whitelist supplied!"
            )

    def check_whitelist(self, username):
        if self.group_whitelist:
            return self.check_group_whitelist(username)
        else:
            return super().check_whitelist(username)

    def check_group_whitelist(self, username):
        """
        If group_whitelist is configured, check if authenticating user is part of group.
        """
        if not self.group_whitelist:
            return False
        for grnam in self.group_whitelist:
            try:
                group = getgrnam(grnam)
            except KeyError:
                self.log.error('No such group: [%s]' % grnam)
                continue
            if username in group.gr_mem:
                return True
        return False

    @gen.coroutine
    def add_user(self, user):
        """Hook called whenever a new user is added

        If self.create_system_users, the user will attempt to be created if it doesn't exist.
        """
        user_exists = yield gen.maybe_future(self.system_user_exists(user))
        if not user_exists:
            if self.create_system_users:
                yield gen.maybe_future(self.add_system_user(user))
            else:
                raise KeyError("User %s does not exist." % user.name)

        yield gen.maybe_future(super().add_user(user))

    @staticmethod
    def system_user_exists(user):
        """Check if the user exists on the system"""
        try:
            pwd.getpwnam(user.name)
        except KeyError:
            return False
        else:
            return True

    def add_system_user(self, user):
        """Create a new local UNIX user on the system.

        Tested to work on FreeBSD and Linux, at least.
        """
        name = user.name
        cmd = [arg.replace('USERNAME', name) for arg in self.add_user_cmd] + [name]
        self.log.info("Creating user: %s", ' '.join(map(pipes.quote, cmd)))
        p = Popen(cmd, stdout=PIPE, stderr=STDOUT)
        p.wait()
        if p.returncode:
            err = p.stdout.read().decode('utf8', 'replace')
            raise RuntimeError("Failed to create system user %s: %s" % (name, err))

    pass


class MyPAM(MyLocalAuthenticator):
    """Default PAMAuthenticator"""
    pass
