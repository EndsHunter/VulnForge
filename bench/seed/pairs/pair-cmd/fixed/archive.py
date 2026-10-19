import subprocess


def unpack(filename):
    subprocess.run(["tar", "xf", "--", filename], check=True)
