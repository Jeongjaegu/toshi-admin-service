if [ ! -d env ]; then
    python3 -m virtualenv env
    env/bin/pip install -r requirements.txt
fi
command -v stunnel >/dev/null 2>&1 || {
    echo >&2 "Unable to find stunnel."
    case $OSTYPE in
        darwin*)
            echo >&2 "Install using: brew install stunnel"
            ;;
    esac
    exit 1
}
if [ ! -d heroku-buildpack-pgsql-stunnel ]; then
    git clone git@github.com:tristan/heroku-buildpack-pgsql-stunnel.git
fi

mkdir -p env/vendor/stunnel/
sed 's@/app/vendor/stunnel@./env/vendor/stunnel@g' heroku-buildpack-pgsql-stunnel/bin/generate-config > env/bin/generate-config
sed -e 's@stunnel4@stunnel@g' -e 's@bin/generate-config@env/bin/generate-config@g' -e 's@vendor/stunnel@env/vendor/stunnel@g' heroku-buildpack-pgsql-stunnel/bin/start-stunnel > env/bin/start-stunnel
chmod +x env/bin/generate-config
chmod +x env/bin/start-stunnel

if [ ! -e .runconfig ]; then
    command -v stunnel >/dev/null 2>&1 || {
        echo >&2 "Missing heroku tools"
        exit 1
    }
    echo -n "Building run config file: .runconfig ..."

    # pull down config details from heroku
    echo "export ID_SERVICE_LOGIN_URL=https://token-id-service.herokuapp.com" > .runconfig

    echo -n "export MAINNET_ID_SERVICE_DATABASE_URL=" >> .runconfig
    heroku config:get DATABASE_URL -a toshi-id-service >> .runconfig
    echo -n "export MAINNET_ETH_SERVICE_DATABASE_URL=" >> .runconfig
    heroku config:get DATABASE_URL -a toshi-eth-service >> .runconfig
    echo -n "export MAINNET_DIR_SERVICE_DATABASE_URL=" >> .runconfig
    heroku config:get DATABASE_URL -a toshi-directory-service >> .runconfig
    echo -n "export MAINNET_REP_SERVICE_DATABASE_URL=" >> .runconfig
    heroku config:get DATABASE_URL -a toshi-reputation-service >> .runconfig

    echo -n "export DEV_ID_SERVICE_DATABASE_URL=" >> .runconfig
    heroku config:get DATABASE_URL -a token-id-service >> .runconfig
    echo -n "export DEV_ETH_SERVICE_DATABASE_URL=" >> .runconfig
    heroku config:get DATABASE_URL -a token-eth-service >> .runconfig
    echo -n "export DEV_DIR_SERVICE_DATABASE_URL=" >> .runconfig
    heroku config:get DATABASE_URL -a token-dir-service >> .runconfig
    echo -n "export DEV_REP_SERVICE_DATABASE_URL=" >> .runconfig
    heroku config:get DATABASE_URL -a token-rep-service >> .runconfig

    echo -n "export INTERNAL_ID_SERVICE_DATABASE_URL=" >> .runconfig
    heroku config:get DATABASE_URL -a token-id-service-development >> .runconfig
    echo -n "export INTERNAL_ETH_SERVICE_DATABASE_URL=" >> .runconfig
    heroku config:get DATABASE_URL -a token-eth-service-development >> .runconfig
    echo -n "export INTERNAL_DIR_SERVICE_DATABASE_URL=" >> .runconfig
    heroku config:get DATABASE_URL -a token-dir-service-development >> .runconfig
    echo -n "export INTERNAL_REP_SERVICE_DATABASE_URL=" >> .runconfig
    heroku config:get DATABASE_URL -a token-rep-service-development >> .runconfig

    echo -n "export MAINNET_ETHEREUM_NODE_URL=" >> .runconfig
    heroku config:get ETHEREUM_NODE_URL -a toshi-eth-service >> .runconfig
    echo -n "export DEV_ETHEREUM_NODE_URL=" >> .runconfig
    heroku config:get ETHEREUM_NODE_URL -a token-eth-service >> .runconfig
    echo -n "export INTERNAL_ETHEREUM_NODE_URL=" >> .runconfig
    heroku config:get ETHEREUM_NODE_URL -a token-eth-service-development >> .runconfig

    echo "export MAINNET_ID_SERVICE_URL=https://toshi-id-service.herokuapp.com" >> .runconfig
    echo "export MAINNET_ETH_SERVICE_URL=https://toshi-eth-service.herokuapp.com" >> .runconfig
    echo "export MAINNET_DIR_SERVICE_URL=https://toshi-dir-service.herokuapp.com" >> .runconfig
    echo "export MAINNET_REP_SERVICE_URL=https://toshi-rep-service.herokuapp.com" >> .runconfig

    echo "export INTERNAL_ID_SERVICE_URL=https://token-id-service-development.herokuapp.com" >> .runconfig
    echo "export INTERNAL_ETH_SERVICE_URL=https://token-eth-service-development.herokuapp.com" >> .runconfig
    echo "export INTERNAL_DIR_SERVICE_URL=https://token-dir-service-development.herokuapp.com" >> .runconfig
    echo "export INTERNAL_REP_SERVICE_URL=https://token-rep-service-development.herokuapp.com" >> .runconfig

    echo "export DEV_ID_SERVICE_URL=https://token-id-service.herokuapp.com" >> .runconfig
    echo "export DEV_ETH_SERVICE_URL=https://token-eth-service.herokuapp.com" >> .runconfig
    echo "export DEV_DIR_SERVICE_URL=https://token-dir-service.herokuapp.com" >> .runconfig
    echo "export DEV_REP_SERVICE_URL=https://token-rep-service.herokuapp.com" >> .runconfig

    echo "done"
fi

source .runconfig

if [ -z $PORT ]; then
    export PORT=5000
fi
export PGSQL_STUNNEL_ENABLED=1
if [ -z $DATABASE_URL ]; then
    export DATABASE_URL=postgresql://toshi:@127.0.0.1/toshi-admin
fi

export STUNNEL_URLS="INTERNAL_ETH_SERVICE_DATABASE_URL INTERNAL_ID_SERVICE_DATABASE_URL INTERNAL_DIR_SERVICE_DATABASE_URL INTERNAL_REP_SERVICE_DATABASE_URL DEV_ETH_SERVICE_DATABASE_URL DEV_ID_SERVICE_DATABASE_URL DEV_DIR_SERVICE_DATABASE_URL DEV_REP_SERVICE_DATABASE_URL MAINNET_ETH_SERVICE_DATABASE_URL MAINNET_ID_SERVICE_DATABASE_URL MAINNET_DIR_SERVICE_DATABASE_URL MAINNET_REP_SERVICE_DATABASE_URL"

#export STUNNEL_LOGLEVEL="debug"
rm -rf /tmp/.s.PGSQL.*
if [ $# -eq 0 ]; then
    # run the server
    if command -v entr >/dev/null 2>&1; then
        env/bin/start-stunnel bash -c "find . -iname '*.py' | entr -r env/bin/python -m toshiadmin"
    else
        env/bin/start-stunnel bash -c "env/bin/python -m toshiadmin"
    fi
else
    PYTHONPATH=. env/bin/start-stunnel env/bin/python $@
fi
