#!/bin/bash
set -e
cd /var/www/html
if [ ! -f wp-config.php ]; then
    wp core config --dbname=wordpress --dbuser=wp --dbpass=wppass --dbhost=db --allow-root
    wp core install --url=http://localhost:8888 --title="php2shell" \
      --admin_user=admin --admin_password=admin --admin_email=admin@lab.local \
      --skip-email --allow-root
fi
wp core version --allow-root
echo "[wpinit] done"
