import asyncio
import aiohttp
import json
import random
import string
import logging
import os
import functools
from urllib.parse import urlencode

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

class App(Sanic):

    def run(self, *args, **kwargs):
        before_start = kwargs.pop('before_start', None)
        async def prepare_db(app, loop):
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
        return super().run(*args, before_start=prepare_db, **kwargs)

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

def to_eth(wei):
    wei = str(parse_int(wei))
    pad = 18 - len(wei)
    if pad < 0:
        eth = wei[:abs(pad)] + "." + wei[abs(pad):]
    else:
        eth = "0." + wei.zfill(18)
    while eth.endswith("0"):
        eth = eth[:-1]
    if eth.endswith("."):
        eth += "0"
    return eth
env.filters['to_eth'] = to_eth

app.static('/public', './public')
app.static('/favicon.ico', './public/favicon.ico')

def fix_avatar_for_user(id_service_url, user, key='avatar'):
    if not user[key]:
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
    resp = await app.http.get(
        '{}/v1/balance/0x{}'.format(conf.urls.eth, '0' * 40), timeout=SERVICE_CHECK_TIMEOUT)
    if resp.status == 200:
        status['eth'] = "OK"
    else:
        status['eth'] = "Error: {}".format(resp.status)
    # id
    resp = await app.http.get(
        '{}/v1/user/0x{}'.format(conf.urls.id, '0' * 40), timeout=SERVICE_CHECK_TIMEOUT)
    if resp.status == 404:
        status['id'] = "OK"
    else:
        status['id'] = "Error: {}".format(resp.status)
    # dir
    resp = await app.http.get(
        '{}/v1/apps/'.format(conf.urls.dir), timeout=SERVICE_CHECK_TIMEOUT)
    if resp.status == 200:
        status['dir'] = "OK"
    else:
        status['dir'] = "Error: {}".format(resp.status)
    # rep
    resp = await app.http.get(
        '{}/v1/timestamp'.format(conf.urls.rep), timeout=SERVICE_CHECK_TIMEOUT)
    if resp.status == 200:
        status['rep'] = "OK"
    else:
        status['rep'] = "Error: {}".format(resp.status)
    # node
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
        raise SanicException("Login Failed", status_code=401)

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
        where_clause = "WHERE " + " OR ".join("last_status = '{}'".format(f) for f in filters)
        if 'unconfirmed' in filters:
            where_clause += " OR last_status IS NULL"
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
                if order[0] == order_by and order[1] == ('DESC' if order_by in negative_user_columns else 'ASC'):
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
    if usr['is_app']:
        async with conf.db.dir.acquire() as con:
            row = await con.fetchrow(
                "SELECT * FROM apps JOIN sofa_manifests ON apps.token_id = sofa_manifests.token_id WHERE apps.token_id = $1",
                token_id)
        if row:
            usr['app'] = row

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

    return html(await env.get_template("user.html").render_async(
        user=usr, txs=txs, tx_count=tx_count, current_user=current_user, environment=conf.name, page="users"))

sortable_apps_columns = ['created', 'name', 'reputation_score', 'featured']
sortable_apps_columns.extend(['-{}'.format(col) for col in sortable_user_columns])
# specify which columns should be sorted in descending order by default
negative_apps_columns = ['created', 'reputation_score', 'featured']

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
        query = '%' + search_query + '%'
        args = [offset, limit, query]
        if order_by:
            query_order = "ORDER BY apps.{} {}".format(*order)
        else:
            # default order by rank
            query_order = "ORDER BY apps.updated"
        sql = ("SELECT * FROM apps "
               "JOIN sofa_manifests ON apps.token_id = sofa_manifests.token_id "
               "WHERE apps.name ilike $3 "
               "{} "
               "OFFSET $1 LIMIT $2"
               .format(query_order))
        count_args = [query]
        count_sql = ("SELECT COUNT(*) FROM apps "
                     "WHERE apps.name ilike $1")
        async with conf.db.dir.acquire() as con:
            print(sql, args)
            rows = await con.fetch(sql, *args)
            count = await con.fetchrow(count_sql, *count_args)
    else:
        async with conf.db.dir.acquire() as con:
            rows = await con.fetch(
                "SELECT * FROM apps JOIN sofa_manifests ON apps.token_id = sofa_manifests.token_id "
                "ORDER BY apps.{} {} NULLS LAST OFFSET $1 LIMIT $2".format(*order),
                offset, limit)
            count = await con.fetchrow(
                "SELECT COUNT(*) FROM apps")
    apps = []
    for row in rows:
        app = fix_avatar_for_user(conf.urls.id, dict(row), 'avatar_url')
        apps.append(app)

    total_pages = (count['count'] // limit) + (0 if count['count'] % limit == 0 else 1)

    def get_qargs(page=page, order_by=order_by, query=search_query, filter=filter_by, as_list=False, as_dict=False):
        qargs = {'page': page}
        if order_by:
            if order_by[0] == '+':
                order_by = order_by[1:]
            elif order_by[0] != '-':
                # toggle sort order
                if order[0] == order_by and order[1] == ('DESC' if order_by in negative_user_columns else 'ASC'):
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

@app.route("/app/add", prefixed=True)
@requires_login
async def add_app_handler_get(request, conf, current_user):
    token_id = request.args.get('token_id', None)
    name = request.args.get('name', None)
    avatar_url = None
    if token_id:
        url = '{}/v1/user/{}'.format(conf.urls.id, token_id)
        resp = await app.http.get(url)
        if resp.status == 200:
            data = await resp.json()
            avatar_url = data['avatar']
        else:
            avatar_url = "{}/identicon/{}.png".format(conf.urls.id, token_id)

    return html(await env.get_template("add_app.html").render_async(
        token_id=token_id, name=name, avatar_url=avatar_url,
        current_user=current_user, environment=conf.name, page="apps"))

@app.route("/app/add", prefixed=True, methods=["POST"])
@requires_login
async def add_app_handler_post(request, conf, current_user):
    token_id = request.form.get('token_id')
    name = request.form.get('name')
    avatar_url = request.form.get('avatar_url')
    description = request.form.get('description')
    #manifest = request.args.get('manifest')
    featured = request.form.get('featured', False)
    if featured is not False:
        featured = True

    context = {
        'current_user': current_user, 'environment': conf.name, 'page': 'apps',
        'token_id': token_id,
        'name': name,
        'avatar_url': avatar_url,
        'description': description,
        'featured': featured
    }

    if token_id is None or name is None or avatar_url is None or description is None: # or manifest is None:
        context['error'] = True
        return html(await env.get_template("add_app.html").render_async(**context))
    else:
        # make sure the token id exists
        url = '{}/v1/user/{}'.format(conf.urls.id, token_id)
        resp = await app.http.get(url)
        if resp.status != 200:
            context['error'] = True
            return html(await env.get_template("add_app.html").render_async(**context))
        else:
            data = await resp.json()

            # TODO: parse given manifest to get these
            init_request = ['paymentAddress', 'language']
            languages = ['en']
            interfaces = ['ChatBot']
            protocol = 'sofa-v1.0'

            payment_address = data['payment_address']
            username = data['username']

            # make sure the id service has this user marked as an app
            if data['is_app'] is False:
                async with conf.db.id.acquire() as con:
                    await con.execute("UPDATE users SET is_app = true WHERE token_id = $1", token_id)
            # save the new app
            async with conf.db.dir.acquire() as con:
                await con.execute(
                    "INSERT INTO apps (token_id, name, description, reputation_score, review_count, featured) "
                    "VALUES ($1, $2, $3, $4, $5, $6) "
                    "ON CONFLICT (token_id) DO UPDATE "
                    "SET name = EXCLUDED.name, description = EXCLUDED.description, "
                    "reputation_score = EXCLUDED.reputation_score, review_count = EXCLUDED.review_count, "
                    "featured = EXCLUDED.featured, "
                    "updated = (now() AT TIME ZONE 'utc')",
                    token_id, name, description, data['reputation_score'], data['review_count'], featured)
                await con.execute(
                    "INSERT INTO sofa_manifests "
                    "(token_id, payment_address, username, init_request, languages, interfaces, protocol, avatar_url) "
                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8) "
                    "ON CONFLICT (token_id) DO UPDATE "
                    "SET payment_address = EXCLUDED.payment_address, username = EXCLUDED.username, "
                    "init_request = EXCLUDED.init_request, languages = EXCLUDED.languages, "
                    "interfaces = EXCLUDED.interfaces, protocol = EXCLUDED.protocol, avatar_url = EXCLUDED.avatar_url",
                    token_id, payment_address, username, init_request, languages, interfaces, protocol, avatar_url)
                await con.execute(
                    "INSERT INTO submissions "
                    "(app_token_id, submitter_token_id) "
                    "VALUES "
                    "($1, $2) "
                    "ON CONFLICT (app_token_id, submitter_token_id) DO NOTHING",
                    token_id, token_id)
            return redirect("/{}/user/{}".format(conf.name, token_id))

@app.route("/app/featured", prefixed=True, methods=["POST"])
@requires_login
async def feature_app_handler_post(request, conf, current_user):
    print(request.form)
    token_id = request.form.get('token_id')
    featured = request.form.get('featured', False)
    if token_id is not None:
        async with conf.db.dir.acquire() as con:
            await con.execute("UPDATE apps SET featured = $2 WHERE token_id = $1", token_id, True if featured else False)
        if 'Referer' in request.headers:
            return redirect(request.headers['Referer'])
        return redirect("/{}/user/{}".format(conf.name, token_id))
    return redirect("/{}/apps".format(conf.name))

@app.route("/app/remove", prefixed=True, methods=["POST"])
@requires_login
async def remove_app_handler_post(request, conf, current_user):
    token_id = request.form.get('token_id')
    if token_id is not None:
        async with conf.db.dir.acquire() as con:
            async with con.transaction():
                await con.execute("DELETE FROM submissions WHERE app_token_id = $1", token_id)
                await con.execute("DELETE FROM sofa_manifests WHERE token_id = $1", token_id)
                await con.execute("DELETE FROM apps WHERE token_id = $1", token_id)
        if 'Referer' in request.headers:
            return redirect(request.headers['Referer'])
        return redirect("/{}/user/{}".format(conf.name, token_id))
    return redirect("/{}/apps".format(conf.name))
