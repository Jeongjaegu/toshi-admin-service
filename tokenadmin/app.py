import asyncio
import math
import aiohttp
import json
import random
import string
import logging
import os

from decimal import Decimal
from fractions import Fraction
from asyncbb.database import prepare_database, create_pool
from asyncbb.log import configure_logger, log as asyncbb_log

from sanic import Sanic
from sanic.exceptions import SanicException
from sanic.log import log as sanic_log
from sanic.response import html, json as json_response, redirect
from sanic.request import Request
from jinja2 import Environment, FileSystemLoader

from tokenbrowser.utils import parse_int

asyncbb_log.setLevel(logging.DEBUG)
configure_logger(sanic_log)

ETHEREUM_NODE_URL = os.getenv("ETHEREUM_NODE_URL", None)
ETH_SERVICE_DATABASE_URL = os.getenv("ETH_SERVICE_DATABASE_URL")
ID_SERVICE_DATABASE_URL = os.getenv("ID_SERVICE_DATABASE_URL")
ADMIN_SERVICE_DATABASE_URL = os.getenv("DATABASE_URL")
ID_SERVICE_LOGIN_URL = os.getenv("ID_SERVICE_LOGIN_URL")
ID_SERVICE_DATA_URL = os.getenv("ID_SERVICE_DATA_URL")
ETH_SERVICE_DATA_URL = os.getenv("ETH_SERVICE_DATA_URL")
asyncbb_log.info("{}".format(ETH_SERVICE_DATABASE_URL))

class App(Sanic):
    def run(self, *args, **kwargs):
        before_start = kwargs.pop('before_start', None)
        async def prepare_db(app, loop):
            app.pool = {}
            app.pool['admin'] = await prepare_database({'dsn': ADMIN_SERVICE_DATABASE_URL})
            app.pool['eth'] = await create_pool(ETH_SERVICE_DATABASE_URL, min_size=1, max_size=3)
            app.pool['id'] = await create_pool(ID_SERVICE_DATABASE_URL, min_size=1, max_size=3)
            app.http = aiohttp.ClientSession()
            if before_start:
                f = before_start()
                if asyncio.iscoroutine(f):
                    await f
        return super().run(*args, before_start=prepare_db, **kwargs)

# monkey patch in path for old versions of sanic
if not hasattr(Request, 'path'):
    from httptools import parse_url

    @property
    def path_monkey_patch(self):
        return self.url

    Request.path = path_monkey_patch

app = App()
env = Environment(enable_async=True, loader=FileSystemLoader('templates'))
env.filters['parse_int'] = parse_int
env.globals.update({'max': max, 'min': min})

def to_eth(wei):
    wei = str(parse_int(wei))
    pad = 17 - len(wei)
    if pad < 0:
        eth = wei[:abs(pad)] + "." + wei[abs(pad):]
    else:
        eth = "0." + wei.zfill(17)
    while eth.endswith("0"):
        eth = eth[:-1]
    if eth.endswith("."):
        eth += "0"
    return eth
env.filters['to_eth'] = to_eth

app.static('/public', './public')
app.static('/favicon.ico', './public/favicon.ico')

def fix_avatar_for_user(user):
    if not user['avatar']:
            user['avatar'] = "{}/identicon/{}.png".format(ID_SERVICE_DATA_URL, user['token_id'])
    elif user['avatar'].startswith('/'):
        user['avatar'] = "{}{}".format(
            ID_SERVICE_DATA_URL,
            user['avatar'])
    return user

async def get_token_user_from_payment_address(address):
    async with app.pool['id'].acquire() as con:
        rows = await con.fetch("SELECT * FROM users WHERE payment_address = $1", address)

    if rows:
        return fix_avatar_for_user(dict(rows[0]))

    return None

def generate_session_id():
    return ''.join([random.choices(string.digits + string.ascii_letters)[0] for x in range(32)])

def requires_login(fn):
    async def check_login(request, *args, **kwargs):
        session_cookie = request.cookies.get('session')
        if session_cookie:
            async with app.pool['admin'].acquire() as con:
                admin = await con.fetchrow("SELECT admins.token_id FROM admins "
                                           "JOIN sessions ON admins.token_id = sessions.token_id "
                                           "WHERE sessions.session_id = $1",
                                           session_cookie)
            if admin:
                url = '{}/v1/user/{}'.format(ID_SERVICE_LOGIN_URL, admin['token_id'])
                resp = await app.http.get(url)
                if resp.status == 200:
                    admin = await resp.json()
                    if admin['custom']['avatar'].startswith('/'):
                        admin['custom']['avatar'] = "{}{}".format(ID_SERVICE_LOGIN_URL, admin['custom']['avatar'])
                else:
                    admin = None
        else:
            admin = None
        if not admin:
            return redirect("/login?redirect={}".format(request.path))
        rval = await fn(request, *args, user=admin, **kwargs)
        return rval
    return check_login

@app.get("/")
@requires_login
async def index(request, user):
    return html(await env.get_template("index.html").render_async(user=user))

@app.get("/login")
async def get_login(request):
    return html(await env.get_template("login.html").render_async())

@app.post("/login")
async def post_login(request):
    token = request.json['auth_token']
    url = '{}/v1/login/verify/{}'.format(ID_SERVICE_LOGIN_URL, token)
    resp = await app.http.get(url)
    if resp.status != 200:
        raise SanicException("Login Failed", status_code=401)

    user = await resp.json()
    token_id = user['token_id']
    session_id = generate_session_id()
    async with app.pool['admin'].acquire() as con:
        admin = await con.fetchrow("SELECT * FROM admins WHERE token_id = $1", token_id)
        if admin:
            await con.execute("INSERT INTO sessions (session_id, token_id) VALUES ($1, $2)",
                              session_id, token_id)
    if admin:
        response = json_response(user)
        response.cookies['session'] = session_id
        #response.cookies['session']['secure'] = True
        return response
    else:
        raise SanicException("Login Failed", status_code=401)

@app.get("/txs")
@requires_login
async def get_txs(request, user):
    page = parse_int(request.args.get('page', None)) or 1
    if page < 1:
        page = 1
    limit = 10
    offset = (page - 1) * limit
    async with app.pool['eth'].acquire() as con:
        rows = await con.fetch(
            "SELECT * FROM transactions ORDER BY created DESC OFFSET $1 LIMIT $2",
            offset, limit)
        count = await con.fetchrow(
            "SELECT COUNT(*) FROM transactions")
    txs = []
    for row in rows:
        tx = dict(row)
        tx['from_user'] = await get_token_user_from_payment_address(tx['from_address'])
        tx['to_user'] = await get_token_user_from_payment_address(tx['to_address'])
        txs.append(tx)

    total_pages = count['count'] // limit

    return html(await env.get_template("txs.html").render_async(txs=txs, user=user, total=count['count'], total_pages=total_pages, page=page))

@app.get("/tx/<tx_hash>")
@requires_login
async def get_tx(request, tx_hash, user):
    context = {'user': user, 'hash': tx_hash}
    async with app.pool['eth'].acquire() as con:
        row = await con.fetchrow(
            "SELECT * FROM transactions WHERE transaction_hash = $1",
            tx_hash)
        bnum = await con.fetchrow(
            "SELECT blocknumber FROM last_blocknumber")
    if row:
        context['db'] = row
    if bnum:
        context['block_number'] = bnum['blocknumber']

    if ETHEREUM_NODE_URL:
        resp = await app.http.post(
            ETHEREUM_NODE_URL,
            headers={'Content-Type': 'application/json'},
            data=json.dumps({
                "jsonrpc": "2.0",
                "id": random.randint(0, 1000000),
                "method": "eth_getTransactionByHash",
                "params": [tx_hash]
            }).encode('utf-8'))
        if resp.status == 200:
            data = await resp.json()
            if 'result' in data:
                if data['result'] is not None:
                    context['node'] = data['result']
            elif 'error' in data:
                context['error'] = data['error']
        else:
            context['error'] = 'Unexpected {} response from node'.format(resp.status)

        if 'node' in context and context['node']['blockNumber'] is not None:
            resp = await app.http.post(
                ETHEREUM_NODE_URL,
                headers={'Content-Type': 'application/json'},
                data=json.dumps({
                    "jsonrpc": "2.0",
                    "id": random.randint(0, 1000000),
                    "method": "eth_getTransactionReceipt",
                    "params": [tx_hash]
                }).encode('utf-8'))
            data = await resp.json()
            if 'result' in data:
                context['receipt'] = data['result']

    if 'node' in context or 'db' in context:
        from_address = context['node']['from'] if 'node' in context else context['db']['from_address']
        to_address = context['node']['to'] if 'node' in context else context['db']['to_address']

        context['from_user'] = await get_token_user_from_payment_address(from_address)
        context['to_user'] = await get_token_user_from_payment_address(to_address)

    return html(await env.get_template("tx.html").render_async(**context))

@app.get("/users")
@requires_login
async def get_users(request, user):
    page = parse_int(request.args.get('page', None)) or 1
    if page < 1:
        page = 1
    limit = 10
    offset = (page - 1) * limit
    async with app.pool['id'].acquire() as con:
        rows = await con.fetch(
            "SELECT * FROM users ORDER BY created DESC OFFSET $1 LIMIT $2",
            offset, limit)
        count = await con.fetchrow(
            "SELECT COUNT(*) FROM users")
    users = []
    for row in rows:
        usr = fix_avatar_for_user(dict(row))
        url = '{}/v1/balance/{}'.format(ETH_SERVICE_DATA_URL, usr['payment_address'])
        resp = await app.http.get(url)
        if resp.status == 200:
            usr['balance'] = await resp.json()

        users.append(usr)

    total_pages = count['count'] // limit

    return html(await env.get_template("users.html").render_async(users=users, user=user, total=count['count'], total_pages=total_pages, page=page))

@app.get("/user/<token_id>")
@requires_login
async def get_user(request, token_id, user):
    async with app.pool['id'].acquire() as con:
        row = await con.fetchrow(
            "SELECT * FROM users WHERE token_id = $1", token_id)
    if not row:
        return html(await env.get_template("user.html").render_async(user=user))
    usr = fix_avatar_for_user(dict(row))
    url = '{}/v1/balance/{}'.format(ETH_SERVICE_DATA_URL, usr['payment_address'])
    resp = await app.http.get(url)
    if resp.status == 200:
        usr['balance'] = await resp.json()

    async with app.pool['eth'].acquire() as con:
        txrows = await con.fetch(
            "SELECT * FROM transactions WHERE from_address = $3 OR to_address = $3 ORDER BY created DESC OFFSET $1 LIMIT $2",
            0, 10, usr['payment_address'])
    txs = []
    for txrow in txrows:
        tx = dict(txrow)
        if tx['from_address'] != usr['payment_address']:
            tx['from_user'] = await get_token_user_from_payment_address(tx['from_address'])
        else:
            tx['from_user'] = usr
        if tx['to_address'] != usr['payment_address']:
            tx['to_user'] = await get_token_user_from_payment_address(tx['to_address'])
        else:
            tx['to_user'] = usr
        txs.append(tx)

    return html(await env.get_template("user.html").render_async(token_user=usr, txs=txs, user=user))
