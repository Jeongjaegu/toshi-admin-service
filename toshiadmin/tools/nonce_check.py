from toshi.utils import parse_int
import json
import random
from toshiadmin.app import app

async def check_account_nonces(conf, dryrun=False):
    async with conf.db.id.acquire() as con:
        users = await con.fetch("SELECT toshi_id, payment_address FROM users")

    last_percent = -1
    async with conf.db.eth.acquire() as con:
        tr = con.transaction()
        await tr.start()
        for i, user in enumerate(users):
            percent = int((i / len(users)) * 100)
            if percent != last_percent:
                print("Progress: {}/{} ({}%)".format(i, len(users), percent))
                last_percent = percent
            from_address = user['payment_address']
            resp = await app.http.post(
                conf.urls.node,
                headers={'Content-Type': 'application/json'},
                data=json.dumps({
                    "jsonrpc": "2.0",
                    "id": random.randint(0, 1000000),
                    "method": "eth_getTransactionCount",
                    "params": [from_address]
                }).encode('utf-8'))
            if resp.status == 200:
                data = await resp.json()
                if 'result' in data and data['result'] is not None:
                    nonce = parse_int(data['result'])

                    res = await con.execute("UPDATE transactions SET last_status = 'error' WHERE from_address = $1 AND nonce >= $2 AND last_status != 'error'",
                                            from_address, nonce)
                    if res != "UPDATE 0":
                        print("{}|{}: {}".format(user['toshi_id'], from_address, res))

        if dryrun:
            await tr.rollback()
        else:
            await tr.commit()

if __name__ == '__main__':
    from toshiadmin.tools import tool_start
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option('--dryrun', action="store_true", dest="dryrun", default=False)
    tool_start(check_account_nonces, parser)
