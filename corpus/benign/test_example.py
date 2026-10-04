import hashlib


def test_digest_is_stable():
    assert hashlib.sha256(b"abc").hexdigest() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_url_is_wellformed():
    url = "https://example.com/search?q=widgets&page=2"
    assert url.startswith("https://")
