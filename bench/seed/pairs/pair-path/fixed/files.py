import os

ROOT = "/data"


def read_doc(name):
    path = os.path.normpath(os.path.join(ROOT, name))
    if not path.startswith(ROOT + os.sep):
        raise ValueError("outside root")
    with open(path) as handle:
        return handle.read()
