#!/usr/bin/env bash
set -o errexit

echo "Installing dependencies..."
pip install -r requirements.txt

echo "Running database migrations..."
python manage.py migrate --noinput

echo "Creating superuser if not exists..."
python manage.py create_admin

echo "Collecting static files..."
python manage.py collectstatic --noinput
