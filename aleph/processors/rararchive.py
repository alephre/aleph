from rarfile import RarFile

from aleph.processors.archive import Archive


class RarArchive(Archive):

    name = "rararchive"
    default_options = {
        "enabled": True,
        "passwords": ["infected", "evil", "virus", "malicious"],
    }
    filetypes = ["application/x-rar"]

    def setup(self):
        self.engine = RarFile

    def tag_archive(self):
        self.add_tag("archive")
        self.add_tag("rar")
