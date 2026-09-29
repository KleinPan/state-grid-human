from custom_components.state_grid_human.captcha import CaptchaSession, normalize_clicks


def test_normalize_clicks_accepts_source_dimensions():
    assert normalize_clicks(
        [{"x": 0, "y": 0}, {"x": 309, "y": 199}],
        width=310,
        height=200,
    ) == [{"x": 0, "y": 0}, {"x": 309, "y": 199}]


def test_normalize_clicks_rejects_out_of_bounds():
    try:
        normalize_clicks([{"x": 310, "y": 100}], width=310, height=200)
    except ValueError as err:
        assert str(err) == "click outside captcha"
    else:
        raise AssertionError("expected ValueError")


def test_captcha_session_defaults_to_five_minute_ttl():
    session = CaptchaSession(
        flow_id="flow",
        login_key="key",
        account="account",
        password="password",
    )
    assert not session.expired(ttl=300)
