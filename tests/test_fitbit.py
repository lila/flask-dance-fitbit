import pytest


def test_index_unauthorized(app):
    with app.test_client() as client:
        response = client.get("/", base_url="https://example.com")

    assert response.status_code == 302
    redirect = response.headers.get("Location", None)
    assert redirect == "https://example.com/login/fitbit"


@pytest.mark.usefixtures("fitbit_authorized", "betamax_record_flask_dance")
def test_index_authorized(app):
    with app.test_client() as client:
        response = client.get("/", base_url="https://example.com")

    assert response.status_code == 200
    text = response.get_data(as_text=True)
    assert text == "You are @lila on GitHub"
