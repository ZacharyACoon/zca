import pathlib
from os import makedirs


class CAPaths(object):
    """handle directory structure for the ca"""

    def init_organization_name_paths(self, organization_name):
        """initialize path information based on organization name"""

        self.organization_name = organization_name
        self.root_dir = pathlib.Path.cwd() / f'{self.organization_name}_ca' / 'root'
        self.root_key_file = self.root_dir / f'{self.organization_name}_root_key.pem'
        self.root_certificate_dir = self.root_dir /  'certificates'
        makedirs(self.root_certificate_dir, mode=0o775, exist_ok=True)

        self.intermediaries_dir = self.root_dir / 'intermediaries'
        makedirs(self.intermediaries_dir, mode=0o775, exist_ok=True)

    def init_intermediary_paths(self, intermediary):
        """initialize path information based on organization, intermediary name"""

        if not hasattr(self, "organization_name"):
            raise Exception("organization_name not intialized")
        self.intermediary = intermediary
        self.intermediary_dir = self.intermediaries_dir / self.intermediary
        self.intermediary_key_file = self.intermediary_dir / f"{self.organization_name}_{self.intermediary}_key.pem"
        self.intermediary_certificate_dir = self.intermediary_dir / 'certificates'
        makedirs(self.intermediary_certificate_dir, mode=0o775, exist_ok=True)

    def init_server_paths(self, server):
        """initializes path information based on organization, intermediary, server name"""

        if not hasattr(self, "intermediary"):
            raise Exception("intermediary not intialized")
        self.server = server
        self.server_dir = self.intermediary_dir / 'servers' / server
        self.server_key_file = self.server_dir / f"{self.organization_name}_{self.intermediary}_{self.server}_key.pem"
        self.server_certificate_dir = self.server_dir / 'certificates'
        makedirs(self.server_certificate_dir, mode=0o775, exist_ok=True)

    def init_user_paths(self, user):
        """initializes path information based on organization, intermediary, server, user name"""

        if not hasattr(self, "intermediary"):
            raise Exception("intermediary not intialized")
        self.user = user
        self.user_dir = self.intermediary_dir / 'users' / user
        self.user_key_file = self.user_dir / f"{self.organization_name}_{self.intermediary}_{self.user}_key.pem"
        self.user_certificate_dir = self.user_dir / 'certificates'
        makedirs(self.user_certificate_dir, mode=0o775, exist_ok=True)