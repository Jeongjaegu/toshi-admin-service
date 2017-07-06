import asyncio
from optparse import OptionParser

from ..app import app, prepare_configs

def tool_start(func, parser=None, include_stage=False):

    if not parser:
        parser = OptionParser()
    parser.add_option('-s', '--stage', dest="stage", default='dev', choices=['live', 'dev'])

    (options, args) = parser.parse_args()

    loop = asyncio.get_event_loop()
    print("Configuring database connections...")
    loop.run_until_complete(prepare_configs(None, app, loop))
    conf = app.configs[options.stage]
    opts = vars(options)
    if not include_stage:
        opts.pop('stage')
    print("Starting...")
    loop.run_until_complete(func(conf, **opts))
    app.http.close()
