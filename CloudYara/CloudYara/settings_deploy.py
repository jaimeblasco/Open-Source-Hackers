SERVICES = {
    "gunicorn":
        {
            "port": 17001,
            "templates": ["{project_dir}/settings_gunicorn.py.template"],
            "before": "./before_deploy.sh",
            "start": "gunicorn -D -c settings_gunicorn.py CloudYara.wsgi:application",
            "after": "./after_deploy.sh",
            "restart": "kill -s SIGHUP {pid}",
        },
    "memcached":
        {
            "pidfile": "{project_dir}/run/memcached.pid",
            "start": "memcached -d -m 32 -s {project_dir}/run/memcached.sock -P {project_dir}/run/memcached.pid",
        }
}

