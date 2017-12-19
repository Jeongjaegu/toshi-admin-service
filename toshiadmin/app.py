import asyncio
import aiohttp
import json
import random
import string
import logging
import os
import functools
import re
import math
import time
from urllib.parse import urlencode, urlunparse

from toshi.database import prepare_database, create_pool
from toshi.log import configure_logger, log as toshi_log

from asyncpg.exceptions import UniqueViolationError
from sanic import Sanic
from sanic.exceptions import SanicException
from sanic.log import log as sanic_log
from sanic.config import Config
from sanic.response import html, json as json_response, redirect
from sanic.request import Request
from jinja2 import Environment, FileSystemLoader

from toshiadmin.utils import process_image

Config.REQUEST_TIMEOUT = 600

from toshi.utils import parse_int

toshi_log.setLevel(logging.DEBUG)
configure_logger(sanic_log)

ADMIN_SERVICE_DATABASE_URL = os.getenv("DATABASE_URL")
ID_SERVICE_LOGIN_URL = os.getenv("ID_SERVICE_LOGIN_URL")

MAINNET_ETHEREUM_NODE_URL = os.getenv("MAINNET_ETHEREUM_NODE_URL")
MAINNET_ETH_SERVICE_DATABASE_URL = os.getenv("MAINNET_ETH_SERVICE_DATABASE_URL")
MAINNET_ID_SERVICE_DATABASE_URL = os.getenv("MAINNET_ID_SERVICE_DATABASE_URL")
MAINNET_DIR_SERVICE_DATABASE_URL = os.getenv("MAINNET_DIR_SERVICE_DATABASE_URL")
MAINNET_REP_SERVICE_DATABASE_URL = os.getenv("MAINNET_REP_SERVICE_DATABASE_URL")
MAINNET_ID_SERVICE_URL = os.getenv("MAINNET_ID_SERVICE_URL")
MAINNET_ETH_SERVICE_URL = os.getenv("MAINNET_ETH_SERVICE_URL")
MAINNET_DIR_SERVICE_URL = os.getenv("MAINNET_DIR_SERVICE_URL")
MAINNET_REP_SERVICE_URL = os.getenv("MAINNET_REP_SERVICE_URL")

DEV_ETHEREUM_NODE_URL = os.getenv("DEV_ETHEREUM_NODE_URL")
DEV_ETH_SERVICE_DATABASE_URL = os.getenv("DEV_ETH_SERVICE_DATABASE_URL")
DEV_ID_SERVICE_DATABASE_URL = os.getenv("DEV_ID_SERVICE_DATABASE_URL")
DEV_DIR_SERVICE_DATABASE_URL = os.getenv("DEV_DIR_SERVICE_DATABASE_URL")
DEV_REP_SERVICE_DATABASE_URL = os.getenv("DEV_REP_SERVICE_DATABASE_URL")
DEV_ID_SERVICE_URL = os.getenv("DEV_ID_SERVICE_URL")
DEV_ETH_SERVICE_URL = os.getenv("DEV_ETH_SERVICE_URL")
DEV_DIR_SERVICE_URL = os.getenv("DEV_DIR_SERVICE_URL")
DEV_REP_SERVICE_URL = os.getenv("DEV_REP_SERVICE_URL")

INTERNAL_ETHEREUM_NODE_URL = os.getenv("INTERNAL_ETHEREUM_NODE_URL")
INTERNAL_ETH_SERVICE_DATABASE_URL = os.getenv("INTERNAL_ETH_SERVICE_DATABASE_URL")
INTERNAL_ID_SERVICE_DATABASE_URL = os.getenv("INTERNAL_ID_SERVICE_DATABASE_URL")
INTERNAL_DIR_SERVICE_DATABASE_URL = os.getenv("INTERNAL_DIR_SERVICE_DATABASE_URL")
INTERNAL_REP_SERVICE_DATABASE_URL = os.getenv("INTERNAL_REP_SERVICE_DATABASE_URL")
INTERNAL_ID_SERVICE_URL = os.getenv("INTERNAL_ID_SERVICE_URL")
INTERNAL_ETH_SERVICE_URL = os.getenv("INTERNAL_ETH_SERVICE_URL")
INTERNAL_DIR_SERVICE_URL = os.getenv("INTERNAL_DIR_SERVICE_URL")
INTERNAL_REP_SERVICE_URL = os.getenv("INTERNAL_REP_SERVICE_URL")

SERVICE_CHECK_TIMEOUT = 2

class _Pools:
    def __init__(self, eth_db_pool, id_db_pool, dir_db_pool, rep_db_pool):
        self.eth = eth_db_pool
        self.id = id_db_pool
        self.dir = dir_db_pool
        self.rep = rep_db_pool

class _Urls:
    def __init__(self, node_url, id_service_url, eth_service_url, dir_service_url, rep_service_url):
        self.node = node_url
        self.id = id_service_url
        self.eth = eth_service_url
        self.dir = dir_service_url
        self.rep = rep_service_url

class Config:
    def __init__(self, name, eth_db_pool, id_db_pool, dir_db_pool, rep_db_pool, node_url, id_service_url, eth_service_url, dir_service_url, rep_service_url):
        self.name = name
        self.db = _Pools(eth_db_pool, id_db_pool, dir_db_pool, rep_db_pool)
        self.urls = _Urls(node_url, id_service_url, eth_service_url, dir_service_url, rep_service_url)

def add_config(fn):
    async def wrapper(request, *args, **kwargs):
        if request.path.startswith("/mainnet"):
            config = app.configs['mainnet']
        elif request.path.startswith("/dev"):
            config = app.configs['dev']
        elif request.path.startswith("/internal"):
            config = app.configs['internal']
        else:
            raise SanicException("Not Found", status_code=404)
        return await fn(request, config, *args, **kwargs)
    return wrapper

async def prepare_configs(before_start, app, loop):
    app.configs = {}

    app.pool = await prepare_database({'dsn': ADMIN_SERVICE_DATABASE_URL})

    # mainnet
    mainnet_eth = await create_pool(MAINNET_ETH_SERVICE_DATABASE_URL, min_size=1, max_size=3)
    mainnet_id = await create_pool(MAINNET_ID_SERVICE_DATABASE_URL, min_size=1, max_size=3)
    mainnet_dir = None # await create_pool(MAINNET_DIR_SERVICE_DATABASE_URL, min_size=1, max_size=3)
    mainnet_rep = await create_pool(MAINNET_REP_SERVICE_DATABASE_URL, min_size=1, max_size=3)
    app.configs['mainnet'] = Config("mainnet", mainnet_eth, mainnet_id, mainnet_dir, mainnet_rep,
                                    MAINNET_ETHEREUM_NODE_URL,
                                    MAINNET_ID_SERVICE_URL,
                                    MAINNET_ETH_SERVICE_URL,
                                    MAINNET_DIR_SERVICE_URL,
                                    MAINNET_REP_SERVICE_URL)

    # dev
    dev_eth = await create_pool(DEV_ETH_SERVICE_DATABASE_URL, min_size=1, max_size=3)
    dev_id = await create_pool(DEV_ID_SERVICE_DATABASE_URL, min_size=1, max_size=3)
    dev_dir = None # await create_pool(DEV_DIR_SERVICE_DATABASE_URL, min_size=1, max_size=3)
    dev_rep = await create_pool(DEV_REP_SERVICE_DATABASE_URL, min_size=1, max_size=3)
    app.configs['dev'] = Config("dev", dev_eth, dev_id, dev_dir, dev_rep,
                                DEV_ETHEREUM_NODE_URL,
                                DEV_ID_SERVICE_URL,
                                DEV_ETH_SERVICE_URL,
                                DEV_DIR_SERVICE_URL,
                                DEV_REP_SERVICE_URL)

    # internal
    internal_eth = await create_pool(INTERNAL_ETH_SERVICE_DATABASE_URL, min_size=1, max_size=3)
    internal_id = await create_pool(INTERNAL_ID_SERVICE_DATABASE_URL, min_size=1, max_size=3)
    internal_dir = None # await create_pool(INTERNAL_DIR_SERVICE_DATABASE_URL, min_size=1, max_size=3)
    internal_rep = await create_pool(INTERNAL_REP_SERVICE_DATABASE_URL, min_size=1, max_size=3)
    app.configs['internal'] = Config("internal", internal_eth, internal_id, internal_dir, internal_rep,
                                     INTERNAL_ETHEREUM_NODE_URL,
                                     INTERNAL_ID_SERVICE_URL,
                                     INTERNAL_ETH_SERVICE_URL,
                                     INTERNAL_DIR_SERVICE_URL,
                                     INTERNAL_REP_SERVICE_URL)

    # configure http client
    app.http = aiohttp.ClientSession()
    if before_start:
        f = before_start()
        if asyncio.iscoroutine(f):
            await f

class App(Sanic):

    def run(self, *args, **kwargs):
        before_start = kwargs.pop('before_start', None)
        return super().run(*args, before_start=functools.partial(prepare_configs, before_start), **kwargs)

    def route(self, uri, methods=frozenset({'GET'}), host=None, prefixed=False):
        if not uri.startswith('/'):
            uri = '/' + uri
        if prefixed:
            def response(handler):
                handler_name = getattr(handler, '__name__', '')
                handler = add_config(handler)
                mh = functools.partial(handler)
                mh.__name__ = '{}_mainnet'.format(handler_name)
                dh = functools.partial(handler)
                dh.__name__ = '{}_dev'.format(handler_name)
                ih = functools.partial(handler)
                ih.__name__ = '{}_internal'.format(handler_name)
                self.router.add(uri="/mainnet{}".format(uri), methods=methods, handler=mh,
                                host=host)
                self.router.add(uri="/dev{}".format(uri), methods=methods, handler=dh,
                                host=host)
                self.router.add(uri="/internal{}".format(uri), methods=methods, handler=ih,
                                host=host)
            return response
        else:
            return super().route(uri, methods=methods, host=host)

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

def to_eth(wei, points=18):
    wei = str(parse_int(wei))
    pad = 18 - len(wei)
    if pad < 0:
        eth = wei[:abs(pad)] + "." + wei[abs(pad):abs(pad)+points]
    else:
        eth = "0." + wei.zfill(18)[:points]
    while eth.endswith("0"):
        eth = eth[:-1]
    if eth.endswith("."):
        eth += "0"
    return eth
env.filters['to_eth'] = to_eth

app.static('/public', './public')
app.static('/favicon.ico', './public/favicon.ico')

@app.middleware('request')
def force_https(request):
    host = request.headers.get('Host', '')
    # get scheme, first by checking the x-forwarded-proto (from nginx/heroku etc)
    # then falling back on whether or not there is an sslcontext
    scheme = request.headers.get(
        'x-forwarded-proto',
        "https" if request.transport.get_extra_info('sslcontext') else "http")
    if not host.startswith("localhost:") and scheme != "https":
        url = urlunparse((
            "https",
            host,
            request.path,
            None,
            request.query_string,
            None))
        return redirect(url)

def fix_avatar_for_user(id_service_url, user, key='avatar'):
    if key not in user or not user[key]:
        user[key] = "{}/identicon/{}.png".format(id_service_url, user['toshi_id'])
    elif user[key].startswith('/'):
        user[key] = "{}{}".format(
            id_service_url,
            user[key])
    return user

async def get_toshi_user_from_payment_address(conf, address):
    async with conf.db.id.acquire() as con:
        rows = await con.fetch("SELECT * FROM users WHERE payment_address = $1", address)

    if rows:
        return fix_avatar_for_user(conf.urls.id, dict(rows[0]))

    return None

def generate_session_id():
    return ''.join([random.choices(string.digits + string.ascii_letters)[0] for x in range(32)])

def requires_login(fn):
    async def check_login(request, *args, **kwargs):
        session_cookie = request.cookies.get('session')
        if session_cookie:
            async with app.pool.acquire() as con:
                admin = await con.fetchrow("SELECT admins.toshi_id FROM admins "
                                           "JOIN sessions ON admins.toshi_id = sessions.toshi_id "
                                           "WHERE sessions.session_id = $1",
                                           session_cookie)
            if admin:
                url = '{}/v1/user/{}'.format(ID_SERVICE_LOGIN_URL, admin['toshi_id'])
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
        # keep the config object as the first argument
        if len(args) and isinstance(args[0], Config):
            args = (args[0], admin, *args[1:])
        else:
            args = (admin, *args)
        rval = await fn(request, *args, **kwargs)
        return rval
    return check_login

@app.route("/")
@requires_login
async def index(request, user):
    return redirect("/mainnet")

@app.route("/", prefixed=True)
@requires_login
async def liveordev(request, conf, user):

    # get statistics

    async with conf.db.eth.acquire() as con:
        tx24h = await con.fetchrow(
            "SELECT COUNT(*) FROM transactions WHERE created > (now() AT TIME ZONE 'utc') - interval '24 hours'")
        tx7d = await con.fetchrow(
            "SELECT COUNT(*) FROM transactions WHERE created > (now() AT TIME ZONE 'utc') - interval '7 days'")
        tx1m = await con.fetchrow(
            "SELECT COUNT(*) FROM transactions WHERE created > (now() AT TIME ZONE 'utc') - interval '1 month'")
        txtotal = await con.fetchrow(
            "SELECT COUNT(*) FROM transactions")
        last_block = await con.fetchrow("SELECT * FROM last_blocknumber")

    async with conf.db.id.acquire() as con:
        u24h = await con.fetchrow(
            "SELECT COUNT(*) FROM users WHERE created > (now() AT TIME ZONE 'utc') - interval '24 hours'")
        u7d = await con.fetchrow(
            "SELECT COUNT(*) FROM users WHERE created > (now() AT TIME ZONE 'utc') - interval '7 days'")
        u1m = await con.fetchrow(
            "SELECT COUNT(*) FROM users WHERE created > (now() AT TIME ZONE 'utc') - interval '1 month'")
        utotal = await con.fetchrow(
            "SELECT COUNT(*) FROM users")

    users = {
        'day': u24h['count'],
        'week': u7d['count'],
        'month': u1m['count'],
        'total': utotal['count']
    }
    txs = {
        'day': tx24h['count'],
        'week': tx7d['count'],
        'month': tx1m['count'],
        'total': txtotal['count']
    }

    status = {}
    block = {'db': last_block['blocknumber']}
    # check service status
    # eth
    try:
        resp = await app.http.get(
            '{}/v1/balance/0x{}'.format(conf.urls.eth, '0' * 40), timeout=SERVICE_CHECK_TIMEOUT)
        if resp.status == 200:
            status['eth'] = "OK"
        else:
            status['eth'] = "Error: {}".format(resp.status)
    except asyncio.TimeoutError:
        status['eth'] = "Error: timeout"
    # id
    try:
        resp = await app.http.get(
            '{}/v1/user/0x{}'.format(conf.urls.id, '0' * 40), timeout=SERVICE_CHECK_TIMEOUT)
        if resp.status == 404:
            status['id'] = "OK"
        else:
            status['id'] = "Error: {}".format(resp.status)
    except asyncio.TimeoutError:
        status['id'] = "Error: timeout"
    # dir
    try:
        resp = await app.http.get(
            '{}/v1/apps/'.format(conf.urls.dir), timeout=SERVICE_CHECK_TIMEOUT)
        if resp.status == 200:
            status['dir'] = "OK"
        else:
            status['dir'] = "Error: {}".format(resp.status)
    except asyncio.TimeoutError:
        status['dir'] = "Error: timeout"
    # rep
    try:
        resp = await app.http.get(
            '{}/v1/timestamp'.format(conf.urls.rep), timeout=SERVICE_CHECK_TIMEOUT)
        if resp.status == 200:
            status['rep'] = "OK"
        else:
            status['rep'] = "Error: {}".format(resp.status)
    except asyncio.TimeoutError:
        status['rep'] = "Error: timeout"
    # node
    try:
        resp = await app.http.post(
            conf.urls.node,
            headers={'Content-Type': 'application/json'},
            data=json.dumps({
                "jsonrpc": "2.0",
                "id": random.randint(0, 1000000),
                "method": "eth_blockNumber",
                "params": []
            }).encode('utf-8'))
        if resp.status == 200:
            data = await resp.json()
            if 'result' in data:
                if data['result'] is not None:
                    status['node'] = "OK"
                    block['node'] = parse_int(data['result'])
            elif 'error' in data:
                status['node'] = data['error']
        else:
            status['node'] = "Error: {}".format(resp.status)
    except asyncio.TimeoutError:
        status['node'] = "Error: timeout"

    return html(await env.get_template("index.html").render_async(
        current_user=user, environment=conf.name, page="home",
        txs=txs, users=users, status=status, block=block))


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
    toshi_id = user['toshi_id']
    session_id = generate_session_id()
    async with app.pool.acquire() as con:
        admin = await con.fetchrow("SELECT * FROM admins WHERE toshi_id = $1", toshi_id)
        if admin:
            await con.execute("INSERT INTO sessions (session_id, toshi_id) VALUES ($1, $2)",
                              session_id, toshi_id)
    if admin:
        response = json_response(user)
        response.cookies['session'] = session_id
        #response.cookies['session']['secure'] = True
        return response
    else:
        toshi_log.info("Invalid login from: {}".format(toshi_id))
        raise SanicException("Login Failed", status_code=401)

@app.post("/logout")
async def post_logout(request):

    session_cookie = request.cookies.get('session')
    if session_cookie:
        async with app.pool.acquire() as con:
            await con.execute("DELETE FROM sessions "
                              "WHERE sessions.session_id = $1",
                              session_cookie)
        del request.cookies['session']
    return redirect("/login")

@app.route("/config")
@requires_login
async def get_config_home(request, current_user):
    # get list of admins
    async with app.pool.acquire() as con:
        admins = await con.fetch("SELECT * FROM admins")
    users = []
    for admin in admins:
        async with app.configs['mainnet'].db.id.acquire() as con:
            user = await con.fetchrow("SELECT * FROM users WHERE toshi_id = $1", admin['toshi_id'])
        if user is None:
            user = {'toshi_id': admin['toshi_id']}
        users.append(fix_avatar_for_user(app.configs['mainnet'].urls.id, dict(user)))
    return html(await env.get_template("config.html").render_async(
        admins=users,
        current_user=current_user, environment='config', page="home"))

@app.route("/config/admin/<action>", methods=["POST"])
@requires_login
async def post_admin_add_remove(request, current_user, action):
    if 'toshi_id' in request.form:
        toshi_id = request.form.get('toshi_id')
        if not toshi_id:
            SanicException("Bad Arguments", status_code=400)
    elif 'username' in request.form:
        username = request.form.get('username')
        if not username:
            raise SanicException("Bad Arguments", status_code=400)
        if username[0] == '@':
            username = username[1:]
            if not username:
                raise SanicException("Bad Arguments", status_code=400)
        async with app.configs['mainnet'].db.id.acquire() as con:
            user = await con.fetchrow("SELECT * FROM users WHERE username = $1", username)
            if user is None and username.startswith("0x"):
                user = await con.fetchrow("SELECT * FROM users WHERE toshi_id = $1", username)
        if user is None:
            raise SanicException("User not found", status_code=400)
        toshi_id = user['toshi_id']
    else:
        SanicException("Bad Arguments", status_code=400)

    if action == 'add':
        print('adding admin: {}'.format(toshi_id))
        async with app.pool.acquire() as con:
            await con.execute("INSERT INTO admins VALUES ($1) ON CONFLICT DO NOTHING", toshi_id)
    elif action == 'remove':
        print('removing admin: {}'.format(toshi_id))
        async with app.pool.acquire() as con:
            await con.execute("DELETE FROM admins WHERE toshi_id = $1", toshi_id)
            await con.execute("DELETE FROM sessions WHERE toshi_id = $1", toshi_id)
    else:
        raise SanicException("Not Found", status_code=404)

    if 'Referer' in request.headers:
        return redirect(request.headers['Referer'])
    return redirect("/config")

@app.route("/txs", prefixed=True)
@requires_login
async def get_txs(request, conf, user):
    page = parse_int(request.args.get('page', None)) or 1
    if page < 1:
        page = 1
    limit = 10
    offset = (page - 1) * limit
    where_clause = 'WHERE v IS NOT NULL'
    filters = [f for f in request.args.getlist('filter', []) if f in ['confirmed', 'unconfirmed', 'error']]
    if filters:
        where_clause += " AND (" + " OR ".join("status = '{}'".format(f) for f in filters)
        if 'unconfirmed' in filters:
            where_clause += " OR status IS NULL"
        where_clause += ")"

    async with conf.db.eth.acquire() as con:
        rows = await con.fetch(
            "SELECT * FROM transactions {} ORDER BY created DESC OFFSET $1 LIMIT $2".format(where_clause),
            offset, limit)
        count = await con.fetchrow(
            "SELECT COUNT(*) FROM transactions {}".format(where_clause))
    txs = []
    for row in rows:
        tx = dict(row)
        tx['from_user'] = await get_toshi_user_from_payment_address(conf, tx['from_address'])
        tx['to_user'] = await get_toshi_user_from_payment_address(conf, tx['to_address'])
        txs.append(tx)

    total_pages = (count['count'] // limit) + (0 if count['count'] % limit == 0 else 1)

    def get_qargs(page=page, filters=filters, as_list=False, as_dict=False):
        qargs = {'page': page}
        if filters:
            qargs['filter'] = filters
        if as_dict:
            return qargs
        if as_list:
            return qargs.items()
        return urlencode(qargs, True)

    return html(await env.get_template("txs.html").render_async(
        txs=txs, current_user=user, environment=conf.name, page="txs",
        total=count['count'], total_pages=total_pages, current_page=page,
        active_filters=filters, get_qargs=get_qargs))

@app.route("/tx/<tx_hash>", prefixed=True)
@requires_login
async def get_tx(request, conf, current_user, tx_hash):
    context = {'current_user': current_user, 'hash': tx_hash, 'environment': conf.name, 'page': 'txs'}
    async with conf.db.eth.acquire() as con:
        row = await con.fetchrow(
            "SELECT * FROM transactions WHERE hash = $1",
            tx_hash)
        bnum = await con.fetchrow(
            "SELECT blocknumber FROM last_blocknumber")
    if row:
        context['db'] = row
    if bnum:
        context['block_number'] = bnum['blocknumber']

    resp = await app.http.post(
        conf.urls.node,
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
            conf.urls.node,
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

        context['from_user'] = await get_toshi_user_from_payment_address(conf, from_address)
        context['to_user'] = await get_toshi_user_from_payment_address(conf, to_address)

    return html(await env.get_template("tx.html").render_async(**context))

sortable_user_columns = ['created', 'username', 'name', 'location', 'reputation_score']
sortable_user_columns.extend(['-{}'.format(col) for col in sortable_user_columns])
# specify which columns should be sorted in descending order by default
negative_user_columns = ['created', 'reputation_score']

@app.route("/users", prefixed=True)
@requires_login
async def get_users(request, conf, current_user):
    page = parse_int(request.args.get('page', None)) or 1
    if page < 1:
        page = 1
    limit = 10
    offset = (page - 1) * limit
    order_by = request.args.get('order_by', None)
    search_query = request.args.get('query', None)
    filter_by = request.args.get('filter', None)
    order = ('created', 'DESC')
    if order_by:
        if order_by in sortable_user_columns:
            if order_by[0] == '-':
                order = (order_by[1:], 'ASC' if order_by[1:] in negative_user_columns else 'DESC')
            else:
                order = (order_by, 'DESC' if order_by in negative_user_columns else 'ASC')

    if search_query:
        # strip punctuation
        query = ''.join([c for c in search_query if c not in string.punctuation])
        # split words and add in partial matching flags
        query = '|'.join(['{}:*'.format(word) for word in query.split(' ') if word])
        args = [offset, limit, query]
        if order_by:
            query_order = "ORDER BY {} {}".format(*order)
        else:
            # default order by rank
            query_order = "ORDER BY TS_RANK_CD(t1.tsv, TO_TSQUERY($3)) DESC, name, username"
        sql = ("SELECT * FROM "
               "(SELECT * FROM users, TO_TSQUERY($3) AS q "
               "WHERE (tsv @@ q){}) AS t1 "
               "{} "
               "OFFSET $1 LIMIT $2"
               .format(" AND is_app = $4" if filter_by == 'is_app' else "", query_order))
        count_args = [query]
        count_sql = ("SELECT COUNT(*) FROM users, TO_TSQUERY($1) AS q "
                     "WHERE (tsv @@ q){}"
                     .format(" AND is_app = $2" if filter_by == 'is_app' is not None else ""))
        if filter_by == 'is_app':
            args.append(True)
            count_args.append(True)
        async with conf.db.id.acquire() as con:
            rows = await con.fetch(sql, *args)
            count = await con.fetchrow(count_sql, *count_args)
    else:
        async with conf.db.id.acquire() as con:
            rows = await con.fetch(
                "SELECT * FROM users {} ORDER BY {} {} NULLS LAST OFFSET $1 LIMIT $2".format(
                    "WHERE is_app = true" if filter_by == 'is_app' else "", *order),
                offset, limit)
            count = await con.fetchrow(
                "SELECT COUNT(*) FROM users {}".format("WHERE is_app = true" if filter_by == 'is_app' else ""))
    users = []
    for row in rows:
        usr = fix_avatar_for_user(conf.urls.id, dict(row))
        url = '{}/v1/balance/{}'.format(conf.urls.eth, usr['payment_address'])
        resp = await app.http.get(url)
        if resp.status == 200:
            usr['balance'] = await resp.json()

        users.append(usr)

    total_pages = (count['count'] // limit) + (0 if count['count'] % limit == 0 else 1)

    def get_qargs(page=page, order_by=order_by, query=search_query, filter=filter_by, as_list=False, as_dict=False):
        qargs = {'page': page}
        if order_by:
            if order_by[0] == '+':
                order_by = order_by[1:]
            elif order_by[0] != '-':
                # toggle sort order
                if order[0] == order_by and order[1] == ('ASC' if order_by in negative_user_columns else 'DESC'):
                    order_by = '-{}'.format(order_by)
            qargs['order_by'] = order_by
        if query:
            qargs['query'] = query
        if filter:
            qargs['filter'] = filter
        if as_dict:
            return qargs
        if as_list:
            return qargs.items()
        return urlencode(qargs)

    return html(await env.get_template("users.html").render_async(
        users=users, current_user=current_user, environment=conf.name, page="users",
        total=count['count'], total_pages=total_pages, current_page=page, get_qargs=get_qargs))

@app.route("/user/<toshi_id>", prefixed=True)
@requires_login
async def get_user(request, conf, current_user, toshi_id):
    async with conf.db.id.acquire() as con:
        row = await con.fetchrow(
            "SELECT * FROM users WHERE toshi_id = $1", toshi_id)
    if not row:
        return html(await env.get_template("user.html").render_async(current_user=current_user, environment=conf.name, page="users"))
    usr = fix_avatar_for_user(conf.urls.id, dict(row))
    url = '{}/v1/balance/{}'.format(conf.urls.eth, usr['payment_address'])
    resp = await app.http.get(url)
    if resp.status == 200:
        usr['balance'] = await resp.json()

    # get last nonce
    resp = await app.http.post(
        conf.urls.node,
        headers={'Content-Type': 'application/json'},
        data=json.dumps({
            "jsonrpc": "2.0",
            "id": random.randint(0, 1000000),
            "method": "eth_getTransactionCount",
            "params": [usr['payment_address']]
        }).encode('utf-8'))
    data = await resp.json()
    if 'result' in data:
        tx_count = data['result']
    else:
        tx_count = -1

    async with conf.db.eth.acquire() as con:
        txrows = await con.fetch(
            "SELECT * FROM transactions WHERE from_address = $3 OR to_address = $3 ORDER BY created DESC OFFSET $1 LIMIT $2",
            0, 100, usr['payment_address'])
    txs = []
    for txrow in txrows:
        tx = dict(txrow)
        if tx['from_address'] != usr['payment_address']:
            tx['from_user'] = await get_toshi_user_from_payment_address(conf, tx['from_address'])
        else:
            tx['from_user'] = usr
        if tx['to_address'] != usr['payment_address']:
            tx['to_user'] = await get_toshi_user_from_payment_address(conf, tx['to_address'])
        else:
            tx['to_user'] = usr
        txs.append(tx)

    async with conf.db.rep.acquire() as con:
        reviews_given_rows = await con.fetch(
            "SELECT * FROM reviews WHERE reviewer_id = $1", toshi_id)
        reviews_received_rows = await con.fetch(
            "SELECT * FROM reviews WHERE reviewee_id = $1", toshi_id)
    reviews_given = []
    reviews_received = []
    for review in reviews_given_rows:
        async with conf.db.id.acquire() as con:
            reviewee = await con.fetchrow("SELECT * FROM users WHERE toshi_id = $1", review['reviewee_id'])
        if reviewee:
            reviewee = fix_avatar_for_user(conf.urls.id, dict(reviewee))
        else:
            reviewee = fix_avatar_for_user(conf.urls.id, {'toshi_id': review['reviewee_id']})
        reviews_given.append({
            'reviewee': reviewee,
            'rating': review['rating'],
            'review': review['review'],
            'created': review['created']
        })
    for review in reviews_received_rows:
        async with conf.db.id.acquire() as con:
            reviewer = await con.fetchrow("SELECT * FROM users WHERE toshi_id = $1", review['reviewer_id'])
        if reviewer:
            reviewer = fix_avatar_for_user(conf.urls.id, dict(reviewer))
        else:
            reviewer = fix_avatar_for_user(conf.urls.id, {'toshi_id': review['reviewer_id']})
        reviews_received.append({
            'reviewer': reviewer,
            'rating': review['rating'],
            'review': review['review'],
            'created': review['created']
        })

    async with conf.db.id.acquire() as con:
        reports_given_rows = await con.fetch(
            "SELECT users.toshi_id, users.username, users.avatar, reports.details "
            "FROM reports JOIN users "
            "ON reports.reportee_toshi_id = users.toshi_id "
            "WHERE reports.reporter_toshi_id = $1",
            toshi_id)
        reports_received_rows = await con.fetch(
            "SELECT users.toshi_id, users.username, users.avatar, reports.details "
            "FROM reports JOIN users "
            "ON reports.reporter_toshi_id = users.toshi_id "
            "WHERE reports.reportee_toshi_id = $1",
            toshi_id)
    reports_given = [fix_avatar_for_user(conf.urls.id, dict(report)) for report in reports_given_rows]
    reports_received = [fix_avatar_for_user(conf.urls.id, dict(report)) for report in reports_received_rows]

    if usr['is_app']:
        async with conf.db.id.acquire() as con:
            rows = await con.fetch(
                "SELECT * FROM categories JOIN app_categories "
                "ON categories.category_id = app_categories.category_id "
                "WHERE toshi_id = $1", toshi_id)
        categories = ", ".join([row['tag'] for row in rows])
        usr['categories'] = categories

    return html(await env.get_template("user.html").render_async(
        user=usr, txs=txs, tx_count=tx_count,
        reviews_given=reviews_given, reviews_received=reviews_received,
        reports_given=reports_given, reports_received=reports_received,
        current_user=current_user, environment=conf.name, page="users"))

sortable_apps_columns = ['created', 'name', 'reputation_score', 'featured', 'blocked']
sortable_apps_columns.extend(['-{}'.format(col) for col in sortable_apps_columns])
# specify which columns should be sorted in descending order by default
negative_apps_columns = ['created', 'reputation_score', 'featured', 'blocked']

@app.route("/apps", prefixed=True)
@requires_login
async def get_apps(request, conf, current_user):
    page = parse_int(request.args.get('page', None)) or 1
    if page < 1:
        page = 1
    limit = 10
    offset = (page - 1) * limit
    order_by = request.args.get('order_by', None)
    search_query = request.args.get('query', None)
    filter_by = request.args.get('filter', None)
    order = ('created', 'DESC')
    if order_by:
        if order_by in sortable_apps_columns:
            if order_by[0] == '-':
                order = (order_by[1:], 'ASC' if order_by[1:] in negative_apps_columns else 'DESC')
            else:
                order = (order_by, 'DESC' if order_by in negative_apps_columns else 'ASC')

    if search_query:
        # strip punctuation
        query = ''.join([c for c in search_query if c not in string.punctuation])
        # split words and add in partial matching flags
        query = '|'.join(['{}:*'.format(word) for word in query.split(' ') if word])
        args = [offset, limit, query]
        if order_by:
            query_order = "ORDER BY {} {}".format(*order)
        else:
            # default order by rank
            query_order = "ORDER BY TS_RANK_CD(t1.tsv, TO_TSQUERY($3)) DESC, name, username"
        sql = ("SELECT * FROM "
               "(SELECT * FROM users, TO_TSQUERY($3) AS q "
               "WHERE (tsv @@ q) AND is_app = true) AS t1 "
               "{} "
               "OFFSET $1 LIMIT $2"
               .format(query_order))
        count_args = [query]
        count_sql = ("SELECT COUNT(*) FROM users, TO_TSQUERY($1) AS q "
                     "WHERE (tsv @@ q) AND is_app = true")
        async with conf.db.id.acquire() as con:
            rows = await con.fetch(sql, *args)
            count = await con.fetchrow(count_sql, *count_args)
    else:
        async with conf.db.id.acquire() as con:
            rows = await con.fetch(
                "SELECT * FROM users WHERE is_app = true ORDER BY {} {} NULLS LAST OFFSET $1 LIMIT $2".format(*order),
                offset, limit)
            count = await con.fetchrow(
                "SELECT COUNT(*) FROM users WHERE is_app = true")

    apps = []
    for row in rows:
        app = fix_avatar_for_user(conf.urls.id, dict(row))
        apps.append(app)

    total_pages = (count['count'] // limit) + (0 if count['count'] % limit == 0 else 1)

    def get_qargs(page=page, order_by=order_by, query=search_query, filter=filter_by, as_list=False, as_dict=False):
        qargs = {'page': page}
        if order_by:
            if order_by[0] == '+':
                order_by = order_by[1:]
            elif order_by[0] != '-':
                # toggle sort order
                print(order, order_by)
                if order[0] == order_by and order[1] == ('ASC' if order_by in negative_user_columns else 'DESC'):
                    order_by = '-{}'.format(order_by)
            qargs['order_by'] = order_by
        if query:
            qargs['query'] = query
        if filter:
            qargs['filter'] = filter
        if as_dict:
            return qargs
        if as_list:
            return qargs.items()
        return urlencode(qargs)

    return html(await env.get_template("apps.html").render_async(
        apps=apps, current_user=current_user, environment=conf.name, page="apps",
        total=count['count'], total_pages=total_pages, current_page=page, get_qargs=get_qargs))

sortable_dapps_columns = ['created', 'name']
sortable_dapps_columns.extend(['-{}'.format(col) for col in sortable_apps_columns])
# specify which columns should be sorted in descending order by default
negative_dapps_columns = []

@app.route("/dapps", prefixed=True, methods=["GET"])
@requires_login
async def get_dapps(request, conf, current_user):
    page = parse_int(request.args.get('page', None)) or 1
    if page < 1:
        page = 1
    limit = 10
    offset = (page - 1) * limit
    order_by = request.args.get('order_by', None)
    search_query = request.args.get('query', None)
    filter_by = request.args.get('filter', None)
    order = ('created', 'DESC')
    if order_by:
        if order_by in sortable_dapps_columns:
            if order_by[0] == '-':
                order = (order_by[1:], 'ASC' if order_by[1:] in negative_dapps_columns else 'DESC')
            else:
                order = (order_by, 'DESC' if order_by in negative_dapps_columns else 'ASC')

    async with conf.db.id.acquire() as con:
        rows = await con.fetch(
            "SELECT * FROM dapps ORDER BY {} {} NULLS LAST OFFSET $1 LIMIT $2".format(*order),
            offset, limit)
        count = await con.fetchrow(
            "SELECT COUNT(*) FROM dapps")

    dapps = []
    for row in rows:
        dapp = fix_avatar_for_user(conf.urls.id, dict(row))
        dapps.append(dapp)

    total_pages = (count['count'] // limit) + (0 if count['count'] % limit == 0 else 1)

    def get_qargs(page=page, order_by=order_by, query=search_query, filter=filter_by, as_list=False, as_dict=False):
        qargs = {'page': page}
        if order_by:
            if order_by[0] == '+':
                order_by = order_by[1:]
            elif order_by[0] != '-':
                # toggle sort order
                print(order, order_by)
                if order[0] == order_by and order[1] == ('ASC' if order_by in negative_dapps_columns else 'DESC'):
                    order_by = '-{}'.format(order_by)
            qargs['order_by'] = order_by
        if query:
            qargs['query'] = query
        if filter:
            qargs['filter'] = filter
        if as_dict:
            return qargs
        if as_list:
            return qargs.items()
        return urlencode(qargs)

    return html(await env.get_template("dapps.html").render_async(
        dapps=dapps, current_user=current_user, environment=conf.name, page="dapps",
        total=count['count'], total_pages=total_pages, current_page=page, get_qargs=get_qargs))

@app.route("/dapp", prefixed=True, methods=["POST"])
@requires_login
async def create_dapp(request, conf, current_user):
    name = request.form.get('name')
    url = request.form.get('url')
    description = request.form.get('description')

    avatar = request.files.get('avatar')

    async with conf.db.id.acquire() as con:
        seq = await con.fetchrow("SELECT COUNT(*) FROM dapps")
    seq = seq['count'] + 1

    dapp_id = (math.floor(time.time()) * 1000) - 1314220021721
    dapp_id = dapp_id << 23
    dapp_id = dapp_id | 1024
    dapp_id = dapp_id | seq

    toshi_id = "0x{:040x}".format(dapp_id)
    data, cache_hash, format = process_image(avatar.body, avatar.type)

    async with conf.db.id.acquire() as con:
        await con.execute("INSERT INTO avatars (toshi_id, img, hash, format) VALUES ($1, $2, $3, $4) "
                          "ON CONFLICT (toshi_id, hash) DO UPDATE "
                          "SET img = EXCLUDED.img, format = EXCLUDED.format, last_modified = (now() AT TIME ZONE 'utc')",
                          toshi_id, data, cache_hash, format)
        avatar_url = "/avatar/{}_{}.{}".format(toshi_id, cache_hash[:6], 'jpg' if format == 'JPEG' else 'png')
        await con.execute("INSERT INTO dapps (dapp_id, name, url, description, avatar) "
                          "VALUES ($1, $2, $3, $4, $5) ",
                          dapp_id, name, url, description, avatar_url)

    if 'Referer' in request.headers:
        return redirect(request.headers['Referer'])
    return redirect("/{}/dapps".format(conf.name))

@app.route("/dapp/<dapp_id>/delete", prefixed=True, methods=["POST"])
@requires_login
async def delete_dapp(request, conf, current_user, dapp_id):
    async with conf.db.id.acquire() as con:
        await con.execute("DELETE FROM dapps WHERE dapp_id = $1", int(dapp_id))

    if 'Referer' in request.headers:
        return redirect(request.headers['Referer'])
    return redirect("/{}/dapps".format(conf.name))

@app.route("/app/featured", prefixed=True, methods=["POST"])
@requires_login
async def feature_app_handler_post(request, conf, current_user):
    print(request.form)
    toshi_id = request.form.get('toshi_id')
    featured = request.form.get('featured', False)
    if toshi_id is not None:
        async with conf.db.id.acquire() as con:
            await con.execute("UPDATE users SET featured = $2 WHERE toshi_id = $1", toshi_id, True if featured else False)
        if 'Referer' in request.headers:
            return redirect(request.headers['Referer'])
        return redirect("/{}/user/{}".format(conf.name, toshi_id))
    return redirect("/{}/apps".format(conf.name))

@app.route("/app/blocked", prefixed=True, methods=["POST"])
@requires_login
async def blocked_app_handler_post(request, conf, current_user):
    toshi_id = request.form.get('toshi_id')
    blocked = request.form.get('blocked', False)
    if toshi_id is not None:
        async with conf.db.id.acquire() as con:
            async with con.transaction():
                await con.execute("UPDATE users SET blocked = $2 WHERE toshi_id = $1", toshi_id, True if blocked else False)
        if 'Referer' in request.headers:
            return redirect(request.headers['Referer'])
        return redirect("/{}/user/{}".format(conf.name, toshi_id))
    return redirect("/{}/apps".format(conf.name))

@app.route("/app/categories", prefixed=True, methods=["POST"])
@requires_login
async def update_app_categories_handler(request, conf, current_user):
    toshi_id = request.form.get('toshi_id')
    categories = request.form.get('categories', "")
    if toshi_id is not None:

        tags = [s.strip() for s in categories.split(",")]

        async with conf.db.id.acquire() as con:
            categories = await con.fetch("SELECT * FROM categories WHERE tag = ANY($1)", tags)
            categories = [row['category_id'] for row in categories]
            async with con.transaction():
                await con.execute("DELETE FROM app_categories WHERE toshi_id = $1", toshi_id)
                await con.executemany(
                    "INSERT INTO app_categories VALUES ($1, $2) ON CONFLICT DO NOTHING",
                    [(category_id, toshi_id) for category_id in categories])
        if 'Referer' in request.headers:
            return redirect(request.headers['Referer'])
        return redirect("/{}/user/{}".format(conf.name, toshi_id))
    return redirect("/{}/apps".format(conf.name))


@app.route("/reports", prefixed=True)
@requires_login
async def get_reports(request, conf, current_user):
    page = parse_int(request.args.get('page', None)) or 1
    if page < 1:
        page = 1
    limit = 10
    offset = (page - 1) * limit

    sql = ("SELECT * FROM reports "
           "ORDER BY report_id DESC "
           "OFFSET $1 LIMIT $2")
    args = [offset, limit]
    count_sql = ("SELECT COUNT(*) FROM reports")
    count_args = []
    async with conf.db.id.acquire() as con:
        rows = await con.fetch(sql, *args)
        count = await con.fetchrow(count_sql, *count_args)

    reports = []
    for row in rows:
        async with conf.db.id.acquire() as con:
            reporter = await con.fetchrow("SELECT * FROM users WHERE toshi_id = $1", row['reporter_toshi_id'])
            reportee = await con.fetchrow("SELECT * FROM users WHERE toshi_id = $1", row['reportee_toshi_id'])

        reporter = fix_avatar_for_user(conf.urls.id, dict(reporter))
        reportee = fix_avatar_for_user(conf.urls.id, dict(reportee))
        reports.append({
            'reporter': reporter,
            'reportee': reportee,
            'details': row['details'],
            'date': row['date']
        })

    total_pages = (count['count'] // limit) + (0 if count['count'] % limit == 0 else 1)

    def get_qargs(page=page, as_list=False, as_dict=False):
        qargs = {'page': page}
        if as_dict:
            return qargs
        if as_list:
            return qargs.items()
        return urlencode(qargs)

    return html(await env.get_template("reports.html").render_async(
        reports=reports, current_user=current_user, environment=conf.name, page="reports",
        total=count['count'], total_pages=total_pages, current_page=page, get_qargs=get_qargs))

@app.route("/categories", prefixed=True)
@requires_login
async def get_categories(request, conf, current_user):

    language = 'en'

    sql = ("SELECT * FROM categories "
           "JOIN category_names ON categories.category_id = category_names.category_id AND category_names.language = $1"
           "ORDER BY categories.category_id DESC ")

    async with conf.db.id.acquire() as con:
        rows = await con.fetch(sql, language)

    return html(await env.get_template("categories.html").render_async(
        categories=rows, current_user=current_user, environment=conf.name, page="categories"))

@app.route("/categories", prefixed=True, methods=["POST"])
@requires_login
async def update_categories(request, conf, current_user):

    category_name = request.form.get('category', None)
    category_tag = request.form.get('tag', None)
    category_id = request.form.get('id', None)
    should_remove = request.form.get('remove', None)
    language = 'en'

    error = None

    if should_remove is not None:

        if category_id is None:
            error = "Missing category id"
        else:
            category_id = parse_int(category_id)

            async with conf.db.id.acquire() as con:
                await con.fetchval(
                    "DELETE FROM categories WHERE category_id = $1",
                    category_id)

    elif category_tag is None or category_name is None:
        error = "Missing name and tag"

    else:

        # force tags to be lowercase
        category_tag = category_tag.lower()

        if category_id is None:
            try:
                async with conf.db.id.acquire() as con:
                    category_id = await con.fetchval(
                        "INSERT INTO categories (tag) VALUES ($1) RETURNING category_id",
                        category_tag)
            except UniqueViolationError:
                error = "Tag already exists"

        # check again because we only update if the category_id was supplied by the user
        # or the insert statement above succeeded.
        if category_id is not None:

            category_id = parse_int(category_id)

            async with conf.db.id.acquire() as con:
                await con.execute(
                    "INSERT INTO category_names (category_id, name, language) VALUES ($1, $2, $3) "
                    "ON CONFLICT (category_id, language) DO UPDATE SET name = EXCLUDED.name",
                    category_id, category_name, language)

    get_sql = ("SELECT * FROM categories "
               "JOIN category_names ON categories.category_id = category_names.category_id AND category_names.language = $1"
               "ORDER BY categories.tag ASC ")

    async with conf.db.id.acquire() as con:
        rows = await con.fetch(get_sql, language)

    return html(await env.get_template("categories.html").render_async(
        categories=rows, error=error,
        current_user=current_user, environment=conf.name, page="categories"))


@app.route("/migrate", methods=["POST"])
@requires_login
async def migrate_users(request, current_user):

    from_env = request.form.get('from', None)
    to_env = request.form.get('to', None)
    toshi_ids = request.form.get('toshi_ids', None)
    apps_flag = request.form.get('apps', None)
    users_flag = request.form.get('users', None)

    limit = 1000
    offset = 1000 * 1

    if toshi_ids:
        toshi_ids = set(re.findall("0x[a-fA-f0-9]{40}", toshi_ids))
    else:
        toshi_ids = set()

    print("MIGRATING USERS FROM '{}' TO '{}'".format(from_env, to_env))

    async with app.configs[from_env].db.id.acquire() as con:
        if apps_flag == 'on':
            users = await con.fetch("SELECT * FROM users WHERE is_app = TRUE")
            print("APPS", len(users))
            user_rows = list(users)
        else:
            user_rows = []
        if users_flag == 'on':
            users = await con.fetch("SELECT * FROM users WHERE is_app = FALSE OFFSET $1 LIMIT $2", offset, limit)
            print("USERS", len(users))
            user_rows.extend(list(users))
        if len(toshi_ids) > 0:
            users = await con.fetch("SELECT * FROM users WHERE toshi_id = ANY($1)", toshi_ids)
            user_rows.extend(list(users))
        for row in user_rows:
            toshi_ids.add(row['toshi_id'])
        avatar_rows = await con.fetch("SELECT * FROM avatars WHERE toshi_id = ANY($1)", toshi_ids)
        users = []
        avatars = []
        for row in user_rows:
            users.append((row['toshi_id'], row['payment_address'], row['created'], row['updated'], row['username'], row['name'], row['avatar'], row['about'], row['location'], row['is_public'], row['went_public'], row['is_app'], row['featured']))
        for row in avatar_rows:
            avatars.append((row['toshi_id'], row['img'], row['hash'], row['format'], row['last_modified']))

    print("INSERTING {} USERS".format(len(toshi_ids)))

    async with app.configs[to_env].db.id.acquire() as con:
        rval = await con.executemany(
            "INSERT INTO users ("
            "toshi_id, payment_address, created, updated, username, name, avatar, about, location, is_public, went_public, is_app, featured"
            ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) "
            "ON CONFLICT DO NOTHING",
            users)
        print("MIGRATED USERS: {} (of {})".format(rval, len(toshi_ids)))
        rval = await con.executemany(
            "INSERT INTO avatars ("
            "toshi_id, img, hash, format, last_modified"
            ") VALUES ($1, $2, $3, $4, $5) "
            "ON CONFLICT DO NOTHING",
            avatars)
        print("MIGRATED AVATARS: {} (of {})".format(rval, len(avatars)))

    return redirect(request.headers['Referer'] or "/config")
