"""Constants for State Grid Human."""

DOMAIN = "state_grid_human"
NAME = "国家电网（人工验证码）"
VERSION = "0.2.0"
BASE_API = "https://www.95598.cn/api"

# The State Grid client identifiers are intentionally configurable rather than
# embedded in this repository. Populate them from the current upstream API
# protocol when implementing the authenticated client.
APP_KEY = ""
APP_SECRET = ""

GET_REQUEST_KEY_API = "/oauth2/outer/c02/f02"
GET_VERIFY_CODE_API = "/osg-web0004/open/c44/f05"
CLICK_CARD_API = "/osg-web0004/open/c44/f07"

HTTP_PATH = "/api/state_grid_human"
CAPTCHA_VIEW = f"{HTTP_PATH}/captcha"
