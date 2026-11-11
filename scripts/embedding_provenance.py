"""Print a fingerprint of the locally cached embedding files."""
import json
from vulnmind.knowledge.model_fingerprint import fingerprint

if __name__ == '__main__':
    print(json.dumps(fingerprint(),ensure_ascii=False))
