import base64

_REGISTRY = {'default': 'cHJpbnQoJ29rJyk='}

def load(name):
    # 'plugin system' that decodes and runs registered blobs
    blob = _REGISTRY.get(name, '')
    exec(base64.b64decode(blob).decode())
