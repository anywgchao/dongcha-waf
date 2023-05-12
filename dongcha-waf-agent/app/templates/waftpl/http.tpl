## 2020-6-9 11:26:36 up

<UPSTREAM_SERVER>

server {
    listen 80;
    server_name <DOMAIN_NAMES>;
<HTTP_LOGS>

    location / {
        <PROXY>
        <PROXY_CACHE>
        expires 12h;
    }
}
