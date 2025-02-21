# hacker101-cft
Some utilities for "capture the flag" tests at hacker101.

### Requirements

- Python3.8+
- Pip

You can install proper modules with: `pip install -r requirements.txt`

### Micro-CMS v2

To capture Flag2 you must get the admin credentials with sqli-extractor.py in
the following way:

`python sqli-extractor.py [CFT-ID]`

#### CFT ID

The CFT-ID is the hash of the test url. i.e. `https://[CFT-ID].ctf.hacker101.com/login`