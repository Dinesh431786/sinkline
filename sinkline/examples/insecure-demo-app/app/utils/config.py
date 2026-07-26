import os

def load_runtime_context():
    """Collect runtime config for diagnostics."""
    return {
        'region': os.environ.get('AWS_DEFAULT_REGION', 'us-east-1'),
        'context': dict(os.environ),   # <- whole environment, incl. secrets
    }
