#!/bin/bash
set -e
pip install -r requirements.txt | egrep -v "(Requirement already satisfied|Cleaning up)" || true
python manage.py collectstatic --noinput
