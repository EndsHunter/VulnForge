import os

ROOT = "/data"


def read_doc(name):
    base = os.path.basename(name)
    path = os.path.join(ROOT, base)
    with open(path) as handle:
        return handle.read()
