## 2020-6-9 11:26:36 up

<UPSTREAM_SERVER>

server {
       listen 80;
       server_name <DOMAIN_NAMES>;
       add_header Strict-Transport-Security max-age=15768000;
       return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    server_name <DOMAIN_NAMES>;
<HTTP_LOGS>

    <HTTPS_SSL>

    location / {
        <PROXY>
        <PROXY_CACHE>
        expires 12h;
    }
}
