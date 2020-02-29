import asyncio
import base64
import configparser
import redis
from aiohttp import web
import aiohttp_session
import aiohttp_jinja2
import jinja2
from cryptography import fernet
from aiohttp_session.cookie_storage import EncryptedCookieStorage
import utils.bot_common

routes = web.RouteTableDef()
routes.static("/files", "files")
xml = """<?xml version="1.0" ?>
<cross-domain-policy>
    <allow-access-from domain="*" />
</cross-domain-policy>"""
config = configparser.ConfigParser()
config.read("web.ini")
if config["webserver"]["allow_reg"].lower() == "true":
    registation = True
else:
    registation = False


def get_level(exp):
    expSum = 0
    i = 0
    while expSum <= exp:
        i += 1
        expSum += i * 50
    return i


@routes.get("/")
async def index(request):
    session = await aiohttp_session.get_session(request)
    context = {}
    if "token" not in session:
        context["logged_in"] = False
    else:
        context["logged_in"] = True
        context["uid"] = session["uid"]
        context["token"] = session["token"]
        context["update_time"] = config["webserver"]["update_time"]
    return aiohttp_jinja2.render_template("index.html", request,
                                          context=context)


@routes.post("/login")
async def login(request):
    session = await aiohttp_session.new_session(request)
    data = await request.post()
    password = data["password"]
    uid = app["redis"].get(f"auth:{password}")
    if uid == data["login"]:
        session["uid"] = uid
        session["token"] = password
    raise web.HTTPFound("/")


@routes.get("/logout")
async def logout(request):
    session = await aiohttp_session.get_session(request)
    if "token" in session:
        del session["token"]
        del session["uid"]
    raise web.HTTPFound("/")


@routes.get("/register")
async def register(request):
    if not registation:
        return web.Response(text="Регистрация доступна через Telegram: @avalime_bot")
    uid, password = utils.bot_common.new_account(app["redis"])
    return web.Response(text=f"Аккаунт создан, ваш логин - {uid}, "
                             f"пароль - {password}")


@routes.get("/prelogin")
async def prelogin(request):
    if "sid" not in request.query:
        raise web.HTTPClientError()
    try:
        uid = int(request.query["sid"])
    except ValueError:
        raise web.HTTPClientError()
    exp = int(app["redis"].get(f"uid:{uid}:exp"))
    return web.json_response({"user": {"bannerNetworkId": None, "reg": 0,
                                       "paymentGroup": "",
                                       "preloginModuleIds": "", "id": uid,
                                       "avatariaLevel": get_level(exp)}})


@routes.post("/method/{name}")
async def method(request):
    data = await request.post()
    name = request.match_info["name"]
    if name == "friends.getAppUsers":
        return web.json_response({"response": []})
    elif name == "friends.get":
        return web.json_response({"response": {"count": 0, "items": []}})
    elif name == "users.get":
        if data["user_ids"]:
            sid = int(data["user_ids"])
            return web.json_response({"response": [{"id": sid, "sex": 2,
                                                    "first_name": "Павел",
                                                    "last_name": "Дуров",
                                                    "bdate": "10.10.1984"}]})
        return web.json_response({"response": []})
    return web.json_response({"error": {"error_code": 3,
                                        "error_msg": "Method not found"}})


@routes.post("/wall_upload")
async def wall_upload(request):
    return web.json_response({"server": 1, "photo": [{"photo": "darova",
                                                      "sizes": []}],
                              "hash": "darova"})


@routes.post("/auth")
async def auth(request):
    data = await request.json()
    return web.json_response({"jsonrpc": "2.0", "id": 1,
                              "result": data["params"][2]["auth_key"]})


@routes.get("/appconfig.xml")
async def appconfig(request):
    context = {"address": config["webserver"]["web_address"]}
    response = aiohttp_jinja2.render_template("appconfig.xml", request,
                                              context=context)
    response.content_type = "application/xml"
    return response


@routes.get("/crossdomain.xml")
async def crossdomain(requst):
    return web.Response(text=xml)


async def main():
    global app
    app = web.Application()
    app.add_routes(routes)
    app["redis"] = redis.Redis(decode_responses=True)
    fernet_key = fernet.Fernet.generate_key()
    secret_key = base64.urlsafe_b64decode(fernet_key)
    aiohttp_session.setup(app, EncryptedCookieStorage(secret_key))
    aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader("templates"))
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", int(config["webserver"]["web_port"]))
    await site.start()


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.create_task(main())
    loop.run_forever()
