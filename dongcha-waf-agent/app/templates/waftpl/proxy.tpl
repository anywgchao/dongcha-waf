proxy_pass <PROXY_TAG>;
        proxy_redirect off;
        proxy_set_header Host $Host;
        proxy_set_header X-Target $request_uri;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header REMOTE-HOST $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_hide_header X-Frame-Options;
        proxy_set_header X-Forwarded-Proto $scheme;
        add_header X-Cache $upstream_cache_status;

        proxy_http_version 1.1;
        proxy_connect_timeout 30s;
        proxy_read_timeout 86400s;
        proxy_send_timeout 30s;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        #Set Nginx Cache
        proxy_ignore_headers Set-Cookie Cache-Control expires;