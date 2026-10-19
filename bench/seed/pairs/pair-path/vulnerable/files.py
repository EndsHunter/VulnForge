import os

ROOT = "/data"


def read_doc(name):
    path = os.path.join(ROOT, name)
    with open(path) as handle:
        return handle.read()
