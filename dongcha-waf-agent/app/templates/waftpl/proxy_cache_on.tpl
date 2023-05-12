# 开启cache
        proxy_cache static_cache;
        proxy_cache_key $host$uri$is_args$args;
        proxy_cache_valid 200 304 301 302 <PROXY_CACHE_TIME>m;