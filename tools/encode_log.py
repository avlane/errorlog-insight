"""Turn a readable fixture (UTF-8 text) into an ERRORLOG-style file.

    python3 tools/encode_log.py tests/fixtures/src/startup_2019.txt tests/fixtures/startup_2019.log

The output is UTF-16 LE with a byte order mark and CRLF line endings, which is
what SQL Server writes on Windows.
"""
import sys


def encode(text):
    text = text.replace("\r\n", "\n").replace("\n", "\r\n")
    return b"\xff\xfe" + text.encode("utf-16-le")


def main(argv):
    if len(argv) != 3:
        sys.exit(__doc__)
    with open(argv[1], encoding="utf-8", newline="") as f:
        data = encode(f.read())
    with open(argv[2], "wb") as f:
        f.write(data)


if __name__ == "__main__":
    main(sys.argv)
