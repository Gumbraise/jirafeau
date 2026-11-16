FROM php:8.3-fpm-alpine
LABEL org.opencontainers.image.authors="jerome@jutteau.fr"
ARG INI="php"

# base install
RUN apk update && \
    apk add lighttpd && \
    rm -rf /var/cache/apk/* && \
    ln -snf /usr/share/zoneinfo/Etc/UTC /etc/localtime  && \
    echo "UTC" > /etc/timezone

COPY --chmod=550 docker/cleanup.sh docker/run.sh  /
COPY --chmod=640 docker/docker_config.php /docker_config.php
RUN sed -i 's/\r$//' /run.sh /cleanup.sh

COPY docker/${INI}.ini /usr/local/etc/php/php.ini
COPY docker/lighttpd.conf /etc/lighttpd/lighttpd.conf

# Install Jirafeau
WORKDIR /www

# Rebuild regularly: official PHP images ship security fixes (e.g. Oct 2026 PHP2Shell advisories).
RUN --mount=type=bind,source=.,target=/mnt \
    cp -r /mnt/* /www/ && \
    rm -rf /www/docker && \
    rm -f /www/install.php && \
    touch /www/lib/config.local.php && \
    chown -R $(id -u lighttpd):$(id -g www-data) /www && \
    chmod 770 /www && \
    chmod 660 /www/lib/config.local.php

CMD ["/run.sh"]
EXPOSE 80
