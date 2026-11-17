#!/bin/sh
set -e
sleep 10 # avoid running cleaning before first setup
while true
do
    php /www/admin.php clean_expired
    php /www/admin.php clean_async
    # Abandoned async transfers use async_abandoned_ttl (default 1h).
    # Sweep more often than daily so temp storage does not accumulate.
    sleep 3600
done
