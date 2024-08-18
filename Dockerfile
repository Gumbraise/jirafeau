FROM php:8.1-fpm-alpine
LABEL org.opencontainers.image.authors="jerome@jutteau.fr"

# base install
RUN apk update && \
    apk add lighttpd && \
    rm -rf /var/cache/apk/* && \
    ln -snf /usr/share/zoneinfo/Etc/UTC /etc/localtime  && \
    echo "UTC" > /etc/timezone

COPY --chmod=550 docker/cleanup.sh docker/run.sh  /
COPY --chmod=640 docker/docker_config.php /docker_config.php

COPY docker/php.ini /usr/local/etc/php/php.ini
COPY docker/lighttpd.conf /etc/lighttpd/lighttpd.conf

# Install Jirafeau
WORKDIR /www

RUN --mount=type=bind,source=.,target=/mnt \
    cp -r /mnt/* /www/ && \
    rm -rf /www/docker && \
    touch /www/lib/config.local.php && \
    chown -R $(id -u lighttpd).$(id -g www-data) /www && \
    chmod 770 /www

CMD ["/run.sh"]
EXPOSE 80