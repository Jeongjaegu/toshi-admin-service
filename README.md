## Running

### Setup env

```
python3 -m virtualenv env
env/bin/pip install -r requirements.txt
```

### Running

To run the development server:

```
./run.sh
```

The server starts on the default port `5000`, to change this set the
`PORT` environment variable (or edit the `run.sh` script).

Running tools:

```
./run.sh tokenadmin/tools/<tool_name>.py <arguments>
```

`./run.sh` requires the heroku command line utility with access to the
token-services set of apps. If deploying this elsewhere edit the script
to use your personal heroku apps, or create `.runconfig` manually.

`./run.sh` assumes postgresql is running with a `token` user and
`token-admin` database, available via the URI: `postgres://token:@127.0.0.1/token-admin`.
To change this either edit the script to match your desired URI, or set the
`DATABASE_URL` environemnt variable to your desired URI.

## Running on heroku

### Add heroku git

```
heroku git:remote -a <heroku-project-name> -r <remote-name>
```

### Config

NOTE: if you have multiple deploys you need to append
`--app <heroku-project-name>` to all the following commands.

#### Set heroku-16

This requires the heroku-16 beta stack

```
heroku stack:set heroku-16
```

#### Addons

```
heroku addons:create heroku-postgresql:hobby-basic
```

#### Buildpacks

```
heroku buildpacks:add https://github.com/debitoor/ssh-private-key-buildpack.git
heroku buildpacks:add https://github.com/tristan/heroku-buildpack-pgsql-stunnel.git
heroku buildpacks:add heroku/python
heroku buildpacks:add heroku/nodejs

heroku config:set SSH_KEY=$(cat path/to/your/keys/id_rsa | base64)
```

#### Extra Config variables

```
heroku config:set PGSQL_STUNNEL_ENABLED=1
heroku config:set NODE_ENV=development
heroku config:set ID_SERVICE_LOGIN_URL=https://token-id-service.herokuapp.com
heroku config:set DEV_ID_SERVICE_URL=https://token-id-service-development.herokuapp.com
heroku config:set DEV_ETH_SERVICE_URL=https://token-eth-service-development.herokuapp.com
heroku config:set DEV_ID_SERVICE_DATABASE_URL=...
heroku config:set DEV_ETH_SERVICE_DATABASE_URL=...
heroku config:set DEV_ETHEREUM_NODE_URL=...
heroku config:set LIVE_ID_SERVICE_URL=https://token-id-service.herokuapp.com
heroku config:set LIVE_ETH_SERVICE_URL=https://token-eth-service.herokuapp.com
heroku config:set LIVE_ID_SERVICE_DATABASE_URL=...
heroku config:set LIVE_ETH_SERVICE_DATABASE_URL=...
heroku config:set LIVE_ETHEREUM_NODE_URL=...

heroku config:set STUNNEL_URLS="DATABASE_URL DEV_ETH_SERVICE_DATABASE_URL DEV_ID_SERVICE_DATABASE_URL LIVE_ETH_SERVICE_DATABASE_URL LIVE_ID_SERVICE_DATABASE_URL"
```

The `Procfile` and `runtime.txt` files required for running on heroku
are provided.

### Start

```
heroku ps:scale web=1
```
