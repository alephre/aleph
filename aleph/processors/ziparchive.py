from zipfile import ZipFile

from aleph.processors.archive import Archive


class ZipArchive(Archive):

    name = "ziparchive"
    default_options = {
        "enabled": True,
        "passwords": ["infected", "evil", "virus", "malicious"],
    }
    filetypes = ["application/zip"]

    def setup(self):
        self.engine = ZipFile

    def tag_archive(self):
        self.add_tag("archive")
        self.add_tag("zip")
