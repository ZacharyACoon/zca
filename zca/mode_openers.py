import os


def private_file_opener(path, flags):
    print(path)
    return os.open(path, flags=flags, mode=0o400)


def public_file_opener(path, flags):
    print(path)
    return os.open(path, flags=flags, mode=0o444)
