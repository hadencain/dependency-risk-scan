from deprisk.resolver import parse_requirements


def test_pinned_package():
    assert parse_requirements("requests==2.28.0\n") == [("requests", "2.28.0")]


def test_unpinned_package():
    assert parse_requirements("flask>=2.0\n") == [("flask", None)]


def test_bare_package():
    assert parse_requirements("numpy\n") == [("numpy", None)]


def test_skips_comments_and_blanks():
    content = "# comment\n\nrequests==2.28.0\n"
    assert parse_requirements(content) == [("requests", "2.28.0")]


def test_package_with_extras():
    assert parse_requirements("requests[security]==2.28.0\n") == [("requests", "2.28.0")]


def test_skips_options_lines():
    content = "-r other.txt\nrequests==2.28.0\n"
    assert parse_requirements(content) == [("requests", "2.28.0")]


def test_multiple_packages():
    content = "requests==2.28.0\nflask\nnumpy>=1.24\n"
    assert parse_requirements(content) == [
        ("requests", "2.28.0"),
        ("flask", None),
        ("numpy", None),
    ]
