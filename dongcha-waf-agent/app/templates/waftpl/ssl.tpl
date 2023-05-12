#SSL相关配置
    #<CERT_PEM> PEM格式证书位置(/tmp/cert.pem)
    #<KEY_PEM> 私钥位置(/tmp/private.key)
    ssl_certificate   <SSL_CERT_PEM>;
    ssl_certificate_key  <SSL_CERT_KEY>;

    ssl_protocols TLSv1.1 TLSv1.2;
    ssl_session_cache shared:SSL:9m;
    ssl_session_cache shared:ssl_session_cache:10m;
    ssl_session_timeout 5m;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE:ECDH:AES:HIGH:!NULL:!aNULL:!MD5:!ADH:!RC4;
    ssl_prefer_server_ciphers on;
    # ssl_stapling on;
    # ssl_stapling_verify on;