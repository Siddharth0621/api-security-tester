from apisec.tester import APISecurityTester


def test_base_url_is_normalized():
    tester = APISecurityTester("http://127.0.0.1:5000/")
    assert tester.base_url == "http://127.0.0.1:5000"


def test_bearer_token_is_added():
    tester = APISecurityTester(
        "http://127.0.0.1:5000",
        auth_token="test-token"
    )
    assert tester.session.headers["Authorization"] == "Bearer test-token"


def test_bearer_prefix_is_not_duplicated():
    tester = APISecurityTester(
        "http://127.0.0.1:5000",
        auth_token="Bearer test-token"
    )
    assert tester.session.headers["Authorization"] == "Bearer test-token"


def test_add_endpoint():
    tester = APISecurityTester("http://127.0.0.1:5000")

    tester.add_endpoint(
        "/api/health",
        methods=["GET"],
        auth_required=False
    )

    assert len(tester.endpoints) == 1
    assert tester.endpoints[0]["path"] == "/api/health"
    assert tester.endpoints[0]["methods"] == ["GET"]
    assert tester.endpoints[0]["auth_required"] is False