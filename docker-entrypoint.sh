#!/bin/sh
# Container start-up (Render, Fly, Railway, any Docker host).
# 1. Seeds the demo data if the database is empty. On Render's FREE plan the
#    disk is wiped on every restart and after 15 minutes idle, so this runs
#    often; on a host with a persistent disk it runs once.
#    scripts/seed.py itself refuses unless TV_DEMO_MODE=1 (public passwords).
# 2. Starts gunicorn on the port the platform gives us ($PORT, Render uses 10000).
set -e
if [ "${TV_DEMO_MODE}" = "1" ]; then
  python -m scripts.seed
fi
exec gunicorn --bind "0.0.0.0:${PORT:-10000}" --workers 2 --threads 4 --timeout 60 \
     --access-logfile - wsgi:app
