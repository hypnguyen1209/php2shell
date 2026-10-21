FROM ubuntu:26.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
      apache2 libapache2-mod-php8.5 \
      php8.5-cli php8.5-common php8.5-mysql php8.5-mbstring php8.5-xml php8.5-curl \
      curl ca-certificates procps && \
    rm -rf /var/lib/apt/lists/*
RUN curl --retry 3 -fsSL https://wordpress.org/latest.tar.gz | tar xz -C /var/www/ && \
    rm -rf /var/www/html && mv /var/www/wordpress /var/www/html && \
    chown -R www-data:www-data /var/www/html
RUN curl -fsSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
      -o /usr/local/bin/wp && chmod +x /usr/local/bin/wp
RUN a2dismod mpm_event 2>/dev/null; a2enmod mpm_prefork php8.5 rewrite && \
    echo "ServerName localhost" >> /etc/apache2/apache2.conf && \
    printf '<IfModule mpm_prefork_module>\nStartServers 4\nMinSpareServers 2\nMaxSpareServers 4\nMaxRequestWorkers 4\nMaxConnectionsPerChild 0\n</IfModule>\n' \
      > /etc/apache2/mods-available/mpm_prefork.conf
RUN mkdir -p /var/lib/php/sessions && chown www-data:www-data /var/lib/php/sessions && \
    echo "session.save_path = /var/lib/php/sessions" > /etc/php/8.5/apache2/conf.d/99-lab.ini

# Handler mismatch directories + POP gadget class
# Simulates: plugin sets php_serialize in /app, default php handler in /api
# Simulates: plugin class with call_user_func in __destruct (no __wakeup)
RUN mkdir -p /var/www/html/wp-content/app /var/www/html/wp-content/api && \
    printf '<?php\necho "OK";\n' > /var/www/html/wp-content/app/index.php && \
    printf '<?php\nsession_start();\necho "OK";\n' > /var/www/html/wp-content/api/index.php && \
    printf '<?php\nclass WP_Cleanup_Handler {\n    public $callback;\n    public $args;\n    public function __destruct() {\n        if (is_callable($this->callback)) {\n            call_user_func($this->callback, $this->args);\n        }\n    }\n}\n' \
      > /var/www/html/wp-content/gadget.php && \
    chown -R www-data:www-data /var/www/html/wp-content/app /var/www/html/wp-content/api /var/www/html/wp-content/gadget.php

# Per-directory session handler mismatch + auto_prepend_file loads gadget
RUN printf '<Directory /var/www/html/wp-content/app>\n    php_value session.serialize_handler php_serialize\n</Directory>\n<Directory /var/www/html/wp-content/api>\n    php_value session.serialize_handler php\n    php_value auto_prepend_file /var/www/html/wp-content/gadget.php\n</Directory>\n' \
      > /etc/apache2/conf-enabled/chain-c.conf

COPY install-wp.sh /install-wp.sh
RUN chmod +x /install-wp.sh
EXPOSE 80
CMD ["apachectl", "-D", "FOREGROUND"]
