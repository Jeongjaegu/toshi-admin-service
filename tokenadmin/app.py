import asyncio
import aiohttp
import json
import random
import string
import logging
import os
import functools
from urllib.parse import urlencode, urlunparse

from tokenservices.database import prepare_database, create_pool
from tokenservices.log import configure_logger, log as tokenservices_log

from sanic import Sanic
from sanic.exceptions import SanicException
from sanic.log import log as sanic_log
from sanic.response import html, json as json_response, redirect
from sanic.request import Request
from jinja2 import Environment, FileSystemLoader

from tokenservices.utils import parse_int

tokenservices_log.setLevel(logging.DEBUG)
configure_logger(sanic_log)

ADMIN_SERVICE_DATABASE_URL = os.getenv("DATABASE_URL")
ID_SERVICE_LOGIN_URL = os.getenv("ID_SERVICE_LOGIN_URL")

LIVE_ETHEREUM_NODE_URL = os.getenv("LIVE_ETHEREUM_NODE_URL")
LIVE_ETH_SERVICE_DATABASE_URL = os.getenv("LIVE_ETH_SERVICE_DATABASE_URL")
LIVE_ID_SERVICE_DATABASE_URL = os.getenv("LIVE_ID_SERVICE_DATABASE_URL")
LIVE_DIR_SERVICE_DATABASE_URL = os.getenv("LIVE_DIR_SERVICE_DATABASE_URL")
LIVE_REP_SERVICE_DATABASE_URL = os.getenv("LIVE_REP_SERVICE_DATABASE_URL")
LIVE_ID_SERVICE_URL = os.getenv("LIVE_ID_SERVICE_URL")
LIVE_ETH_SERVICE_URL = os.getenv("LIVE_ETH_SERVICE_URL")
LIVE_DIR_SERVICE_URL = os.getenv("LIVE_DIR_SERVICE_URL")
LIVE_REP_SERVICE_URL = os.getenv("LIVE_REP_SERVICE_URL")

DEV_ETHEREUM_NODE_URL = os.getenv("DEV_ETHEREUM_NODE_URL")
DEV_ETH_SERVICE_DATABASE_URL = os.getenv("DEV_ETH_SERVICE_DATABASE_URL")
DEV_ID_SERVICE_DATABASE_URL = os.getenv("DEV_ID_SERVICE_DATABASE_URL")
DEV_DIR_SERVICE_DATABASE_URL = os.getenv("DEV_DIR_SERVICE_DATABASE_URL")
DEV_REP_SERVICE_DATABASE_URL = os.getenv("DEV_REP_SERVICE_DATABASE_URL")
DEV_ID_SERVICE_URL = os.getenv("DEV_ID_SERVICE_URL")
DEV_ETH_SERVICE_URL = os.getenv("DEV_ETH_SERVICE_URL")
DEV_DIR_SERVICE_URL = os.getenv("DEV_DIR_SERVICE_URL")
DEV_REP_SERVICE_URL = os.getenv("DEV_REP_SERVICE_URL")

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
        if request.path.startswith("/live"):
            config = app.configs['live']
        elif request.path.startswith("/dev"):
            config = app.configs['dev']
        else:
            raise SanicException("Not Found", status_code=404)
        return await fn(request, config, *args, **kwargs)
    return wrapper

async def prepare_configs(before_start, app, loop):
    app.configs = {}

    app.pool = await prepare_database({'dsn': ADMIN_SERVICE_DATABASE_URL})
    # live
    live_eth = await create_pool(LIVE_ETH_SERVICE_DATABASE_URL, min_size=1, max_size=3)
    live_id = await create_pool(LIVE_ID_SERVICE_DATABASE_URL, min_size=1, max_size=3)
    live_dir = await create_pool(LIVE_DIR_SERVICE_DATABASE_URL, min_size=1, max_size=3)
    live_rep = await create_pool(LIVE_REP_SERVICE_DATABASE_URL, min_size=1, max_size=3)
    app.configs['live'] = Config("live", live_eth, live_id, live_dir, live_rep,
                                 LIVE_ETHEREUM_NODE_URL,
                                 LIVE_ID_SERVICE_URL,
                                 LIVE_ETH_SERVICE_URL,
                                 LIVE_DIR_SERVICE_URL,
                                 LIVE_REP_SERVICE_URL)

    # dev
    dev_eth = await create_pool(DEV_ETH_SERVICE_DATABASE_URL, min_size=1, max_size=3)
    dev_id = await create_pool(DEV_ID_SERVICE_DATABASE_URL, min_size=1, max_size=3)
    dev_dir = await create_pool(DEV_DIR_SERVICE_DATABASE_URL, min_size=1, max_size=3)
    dev_rep = await create_pool(DEV_REP_SERVICE_DATABASE_URL, min_size=1, max_size=3)
    app.configs['dev'] = Config("dev", dev_eth, dev_id, dev_dir, dev_rep,
                                DEV_ETHEREUM_NODE_URL,
                                DEV_ID_SERVICE_URL,
                                DEV_ETH_SERVICE_URL,
                                DEV_DIR_SERVICE_URL,
                                DEV_REP_SERVICE_URL)

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
                lh = functools.partial(handler)
                lh.__name__ = '{}_live'.format(handler_name)
                dh = functools.partial(handler)
                dh.__name__ = '{}_dev'.format(handler_name)
                self.router.add(uri="/live{}".format(uri), methods=methods, handler=lh,
                                host=host)
                self.router.add(uri="/dev{}".format(uri), methods=methods, handler=dh,
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
        user[key] = "{}/identicon/{}.png".format(id_service_url, user['token_id'])
    elif user[key].startswith('/'):
        user[key] = "{}{}".format(
            id_service_url,
            user[key])
    return user

async def get_token_user_from_payment_address(conf, address):
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
    return redirect("/live")

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
    token_id = user['token_id']
    session_id = generate_session_id()
    async with app.pool.acquire() as con:
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
        tokenservices_log.info("Invalid login from: {}".format(token_id))
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
        async with app.configs['live'].db.id.acquire() as con:
            user = await con.fetchrow("SELECT * FROM users WHERE token_id = $1", admin['token_id'])
        if user is None:
            user = {'token_id': admin['token_id']}
        users.append(fix_avatar_for_user(app.configs['live'].urls.id, dict(user)))
    return html(await env.get_template("config.html").render_async(
        admins=users,
        current_user=current_user, environment='config', page="home"))

@app.route("/config/admin/<action>", methods=["POST"])
@requires_login
async def post_admin_add_remove(request, current_user, action):
    if 'token_id' in request.form:
        token_id = request.form.get('token_id')
        if not token_id:
            SanicException("Bad Arguments", status_code=400)
    elif 'username' in request.form:
        username = request.form.get('username')
        if not username:
            raise SanicException("Bad Arguments", status_code=400)
        if username[0] == '@':
            username = username[1:]
            if not username:
                raise SanicException("Bad Arguments", status_code=400)
        async with app.configs['live'].db.id.acquire() as con:
            user = await con.fetchrow("SELECT * FROM users WHERE username = $1", username)
            if user is None and username.startswith("0x"):
                user = await con.fetchrow("SELECT * FROM users WHERE token_id = $1", username)
        if user is None:
            raise SanicException("User not found", status_code=400)
        token_id = user['token_id']
    else:
        SanicException("Bad Arguments", status_code=400)

    if action == 'add':
        print('adding admin: {}'.format(token_id))
        async with app.pool.acquire() as con:
            await con.execute("INSERT INTO admins VALUES ($1) ON CONFLICT DO NOTHING", token_id)
    elif action == 'remove':
        print('removing admin: {}'.format(token_id))
        async with app.pool.acquire() as con:
            await con.execute("DELETE FROM admins WHERE token_id = $1", token_id)
            await con.execute("DELETE FROM sessions WHERE token_id = $1", token_id)
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
    where_clause = ''
    filters = [f for f in request.args.getlist('filter', []) if f in ['confirmed', 'unconfirmed', 'error']]
    if filters:
        where_clause = "WHERE " + " OR ".join("status = '{}'".format(f) for f in filters)
        if 'unconfirmed' in filters:
            where_clause += " OR status IS NULL"
    async with conf.db.eth.acquire() as con:
        rows = await con.fetch(
            "SELECT * FROM transactions {} ORDER BY created DESC OFFSET $1 LIMIT $2".format(where_clause),
            offset, limit)
        count = await con.fetchrow(
            "SELECT COUNT(*) FROM transactions {}".format(where_clause))
    txs = []
    for row in rows:
        tx = dict(row)
        tx['from_user'] = await get_token_user_from_payment_address(conf, tx['from_address'])
        tx['to_user'] = await get_token_user_from_payment_address(conf, tx['to_address'])
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
            "SELECT * FROM transactions WHERE transaction_hash = $1",
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

        context['from_user'] = await get_token_user_from_payment_address(conf, from_address)
        context['to_user'] = await get_token_user_from_payment_address(conf, to_address)

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

@app.route("/user/<token_id>", prefixed=True)
@requires_login
async def get_user(request, conf, current_user, token_id):
    async with conf.db.id.acquire() as con:
        row = await con.fetchrow(
            "SELECT * FROM users WHERE token_id = $1", token_id)
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
            0, 10, usr['payment_address'])
    txs = []
    for txrow in txrows:
        tx = dict(txrow)
        if tx['from_address'] != usr['payment_address']:
            tx['from_user'] = await get_token_user_from_payment_address(conf, tx['from_address'])
        else:
            tx['from_user'] = usr
        if tx['to_address'] != usr['payment_address']:
            tx['to_user'] = await get_token_user_from_payment_address(conf, tx['to_address'])
        else:
            tx['to_user'] = usr
        txs.append(tx)

    async with conf.db.rep.acquire() as con:
        reviews_given_rows = await con.fetch(
            "SELECT * FROM reviews WHERE reviewer_id = $1", token_id)
        reviews_received_rows = await con.fetch(
            "SELECT * FROM reviews WHERE reviewee_id = $1", token_id)
    reviews_given = []
    reviews_received = []
    for review in reviews_given_rows:
        async with conf.db.id.acquire() as con:
            reviewee = await con.fetchrow("SELECT * FROM users WHERE token_id = $1", review['reviewee_id'])
        if reviewee:
            reviewee = fix_avatar_for_user(conf.urls.id, dict(reviewee))
        else:
            reviewee = fix_avatar_for_user(conf.urls.id, {'token_id': review['reviewee_id']})
        reviews_given.append({
            'reviewee': reviewee,
            'rating': review['rating'],
            'review': review['review'],
            'created': review['created']
        })
    for review in reviews_received_rows:
        async with conf.db.id.acquire() as con:
            reviewer = await con.fetchrow("SELECT * FROM users WHERE token_id = $1", review['reviewer_id'])
        if reviewer:
            reviewer = fix_avatar_for_user(conf.urls.id, dict(reviewer))
        else:
            reviewer = fix_avatar_for_user(conf.urls.id, {'token_id': review['reviewer_id']})
        reviews_received.append({
            'reviewer': reviewer,
            'rating': review['rating'],
            'review': review['review'],
            'created': review['created']
        })

    async with conf.db.id.acquire() as con:
        reports_given_rows = await con.fetch(
            "SELECT users.token_id, users.username, users.avatar, reports.details "
            "FROM reports JOIN users "
            "ON reports.reportee_token_id = users.token_id "
            "WHERE reports.reporter_token_id = $1",
            token_id)
        reports_received_rows = await con.fetch(
            "SELECT users.token_id, users.username, users.avatar, reports.details "
            "FROM reports JOIN users "
            "ON reports.reporter_token_id = users.token_id "
            "WHERE reports.reportee_token_id = $1",
            token_id)
    reports_given = [fix_avatar_for_user(conf.urls.id, dict(report)) for report in reports_given_rows]
    reports_received = [fix_avatar_for_user(conf.urls.id, dict(report)) for report in reports_received_rows]

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

@app.route("/app/featured", prefixed=True, methods=["POST"])
@requires_login
async def feature_app_handler_post(request, conf, current_user):
    print(request.form)
    token_id = request.form.get('token_id')
    featured = request.form.get('featured', False)
    if token_id is not None:
        async with conf.db.id.acquire() as con:
            await con.execute("UPDATE users SET featured = $2 WHERE token_id = $1", token_id, True if featured else False)
        if 'Referer' in request.headers:
            return redirect(request.headers['Referer'])
        return redirect("/{}/user/{}".format(conf.name, token_id))
    return redirect("/{}/apps".format(conf.name))

@app.route("/app/blocked", prefixed=True, methods=["POST"])
@requires_login
async def blocked_app_handler_post(request, conf, current_user):
    token_id = request.form.get('token_id')
    blocked = request.form.get('blocked', False)
    if token_id is not None:
        async with conf.db.id.acquire() as con:
            async with con.transaction():
                await con.execute("UPDATE users SET blocked = $2 WHERE token_id = $1", token_id, True if blocked else False)
        if 'Referer' in request.headers:
            return redirect(request.headers['Referer'])
        return redirect("/{}/user/{}".format(conf.name, token_id))
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
            reporter = await con.fetchrow("SELECT * FROM users WHERE token_id = $1", row['reporter_token_id'])
            reportee = await con.fetchrow("SELECT * FROM users WHERE token_id = $1", row['reportee_token_id'])

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
