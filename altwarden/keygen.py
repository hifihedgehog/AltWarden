"""Print a new MASTER_KEY for .env. Run with: python -m altwarden.keygen"""
from .crypto import new_master_key

if __name__ == "__main__":
    print(new_master_key())
