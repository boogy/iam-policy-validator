from iam_validator.core.aws_service.parsers import ServiceParser

ACTIONS = ["GetObject", "GetBucket", "PutObject", "getobjectacl"]


def test_single_char_wildcard_matches_exactly_one_character():
    parser = ServiceParser()
    ok, matched = parser.match_wildcard_action("Get?bject", ACTIONS)
    assert ok is True
    assert matched == ["GetObject"]


def test_single_char_wildcard_does_not_match_multiple_characters():
    parser = ServiceParser()
    ok, matched = parser.match_wildcard_action("Get?", ACTIONS)
    assert ok is False
    assert matched == []


def test_star_still_matches_zero_or_more():
    parser = ServiceParser()
    _, matched = parser.match_wildcard_action("Get*", ACTIONS)
    assert set(matched) == {"GetObject", "GetBucket", "getobjectacl"}


def test_pattern_compilation_is_cached():
    from iam_validator.core.aws_matching import compile_iam_glob

    compile_iam_glob.cache_clear()
    parser = ServiceParser()
    for _ in range(50):
        parser.match_wildcard_action("Get*", ACTIONS)
    assert compile_iam_glob.cache_info().misses == 1
    assert compile_iam_glob.cache_info().hits == 49
