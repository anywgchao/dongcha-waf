# 简介

WAF框架Agent
* 主要用于对接WAF Manager平台，协助WAF Manager平台在多个WAF 集群节点上，添加站点、修改站点、删除站点、添加证书、修改证书、删除证书等功能
* 监控各个节点CPU、磁盘、内存、机器健康等信息，传输到WAF Manager平台上。
* 重启/重载WAF服务

## 安装

生成虚拟环境（pyton3.7 开发）

python3 -m venv venv

source venv/bin/activate

### 安装依赖包

pip install -r requirements.txt

### 启动服务

功能，包括命令行工具、 交互式Console接口、 WebAPI接口。


### 重加载WAF服务

接口：/waf/v1/reload

```request：
{
	"ops_code": 200
}
```

```response：
{
  "data": "",
  "msg": "Reload Success",
  "status": 200
}

:return code
200     正确返回
400     request Body 非JSON
550     表单验证失败
554     WAF 重载失败
```

### 重启WAF服务（暂不可用）

接口：/waf/v1/restart

```request:
{
    "task_id": "8dc81648-c52d-4595-9805-fd048231c7e9"           #任务ID
}
```

```response：
{
  "data": "",
  "msg": "Reload Success",
  "status": 200
}


:return code
200     正确返回
400     request Body 非JSON
550     表单验证失败
551     WAF 重启失败
```

### 添加站点-更新站点则覆盖

接口：/waf/v1/site/add

```request:
{
  "site_uuid": "5bb2d573-d9ff-4a28-b14b-5ab5ec855c03",
  "domain_name": [
    "aaa.daboluo.me",
    "bbb.daboluo.me"
  ],
  "protocol_type": [
    "http",
    "https"
  ],
  "certificate_uuid": "5bb2d573-d9ff-4a28-b14b-5ab5ec855c02",
  "upstream_url": [
    "192.168.1.1:8082",
    "192.168.1.2:8083"
  ],
  "proxy_cache": "off",
  "proxy_cache_time": 1
}
```

```response：
{
  "data": "",
  "msg": "Reload Success",
  "status": 200
}


:return code
200     正确返回
550     表单验证失败
551     新增站点配置后，无法重载服务
552     站点域名存在重复
553     站点存储路径未找到
554     添加站点失败
```

### 删除站点

接口：/waf/v1/site/delete

```request:
{
  "site_uuid": "5bb2d573-d9ff-4a28-b14b-5ab5ec855c03"
}
```

```response：
{
  "data": "",
  "msg": "Reload Success",
  "status": 200
}

:return code
200     正确返回
550     表单验证失败
551     删除站点后，无法重载服务
554     删除站点失败
```

### 查看站点-配置文件内容

接口：/waf/v1/site/view

```request:
{
  "site_uuid": "5bb2d573-d9ff-4a28-b14b-5ab5ec855c03"
}
```

```response：
{
  "data": "",
  "msg": "Reload Success",
  "status": 200
}

:return code
200     正确返回
550     表单验证失败
551     站点文件不存在
554     查看站点配置失败
```

### 更新站点-配置文件内容

接口：/waf/v1/site/update

```request:
{
  "site_uuid": "5bb2d573-d9ff-4a28-b14b-5ab5ec855c03",
  "site_conf_data": "## 2020-6-9 11:26:36 up\n\nupstream 5bb2d573-d9ff-4a28-b14b-5ab5ec855c03 {\n        # server 13.7.42.92 max_fails=1 fail_timeout=10s;\n        # server 13.7.42.91 max_fails=1 fail_timeout=10s;\n        # server 192.168.1.158 backup;\n        server 192.168.1.1:8082 max_fails=3 fail_timeout=60 weight=1;\n        server 192.168.1.2:8083 max_fails=3 fail_timeout=60 weight=1;\n\n        keepalive 10240;\n}\n\nserver {\n       listen 80;\n       server_name aaa.daboluo.me bbb.daboluo.me;\n       add_header Strict-Transport-Security max-age=15768000;\n       return 301 https://$server_name$request_uri;\n}\n\nserver {\n    listen 443 ssl;\n    server_name aaa.daboluo.me bbb.daboluo.me;\n    access_log /var/log/nginx/access_5bb2d573-d9ff-4a28-b14b-5ab5ec855c03.log json;\n    error_log /var/log/nginx/error_5bb2d573-d9ff-4a28-b14b-5ab5ec855c03.log;\n\n    #SSL相关配置\n    #<CERT_PEM> PEM格式证书位置(/tmp/cert.pem)\n    #<KEY_PEM> 私钥位置(/tmp/private.key)\n    ssl_certificate   /etc/nginx/cert_key/5bb2d573-d9ff-4a28-b14b-5ab5ec855c02.pem;\n    ssl_certificate_key  /etc/nginx/cert_key/5bb2d573-d9ff-4a28-b14b-5ab5ec855c02.key;\n\n    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n    ssl_session_cache shared:SSL:9m;\n    ssl_session_cache shared:ssl_session_cache:10m;\n    ssl_session_timeout 5m;\n    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE:ECDH:AES:HIGH:!NULL:!aNULL:!MD5:!ADH:!RC4;\n    ssl_prefer_server_ciphers on;\n    # ssl_stapling on;\n    # ssl_stapling_verify on;\n\n    location / {\n        proxy_pass http://5bb2d573-d9ff-4a28-b14b-5ab5ec855c03;\n        proxy_redirect off;\n        proxy_set_header Host $Host;\n        proxy_set_header X-Target $request_uri;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header REMOTE-HOST $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_hide_header X-Frame-Options;\n        proxy_set_header X-Forwarded-Proto $scheme;\n        add_header X-Cache $upstream_cache_status;\n\n        proxy_http_version 1.1;\n        proxy_connect_timeout 30s;\n        proxy_read_timeout 86400s;\n        proxy_send_timeout 30s;\n        proxy_set_header Upgrade $http_upgrade;\n        proxy_set_header Connection \"upgrade\";\n\n        #Set Nginx Cache\n        proxy_ignore_headers Set-Cookie Cache-Control expires;\n        # 禁用cache\n        add_header Cache-Control no-cache;\n        expires 12h;\n    }\n}\n"
}
```

```response：
{
  "data": "",
  "msg": "Reload Success",
  "status": 200
}

:return code
200     正确返回
550     表单验证失败
551     站点文件不存在
201     站点配置内容错误，还原回之前配置
554     更新站点配置失败
```

### 添加证书

接口：/waf/v1/cert/add

```request:
{
  "certificate_uuid": "5bb2d573-d9ff-4a28-b14b-5ab5ec855c02",
  "certificate_pem": "-----BEGIN CERTIFICATE-----\r\nMIIDjDCCAnQCCQDdjQmieM+NYjANBgkqhkiG9w0BAQsFADCBhzELMAkGA1UEBhMC\r\nQ04xCzAJBgNVBAgMAkJKMQswCQYDVQQHDAJCSjESMBAGA1UECgwJaXNoYW5zb25n\r\nMQwwCgYDVQQLDANkZXYxFjAUBgNVBAMMDWlzaGFuc29uZy5jb20xJDAiBgkqhkiG\r\n9w0BCQEWFXN1cHBvcnRAaXNoYW5zb25nLmNvbTAeFw0xOTAxMDMwMjI4NDVaFw0y\r\nODEyMzEwMjI4NDVaMIGHMQswCQYDVQQGEwJDTjELMAkGA1UECAwCQkoxCzAJBgNV\r\nBAcMAkJKMRIwEAYDVQQKDAlpc2hhbnNvbmcxDDAKBgNVBAsMA2RldjEWMBQGA1UE\r\nAwwNaXNoYW5zb25nLmNvbTEkMCIGCSqGSIb3DQEJARYVc3VwcG9ydEBpc2hhbnNv\r\nbmcuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzlHVYB7nKYj4\r\nOWX965DGTfesvv7o5Cj2rHk6kxncqqsEt5+cs/LOrqD0udNaovAjXkvCcKzuR6nf\r\nqda0DePH1KgZfn/pCT63iuj4NE8hrvtvDMInTo9b5vNIkcHKhC0WvaAkk/LNAiuj\r\nqUNubIN+iLCIFuQC03nN/UOx/k5CCiom/2TO6tluoTMyLb/vh/xqXg96jbp0vh/H\r\n9cq2SIL11tCCg73dSx7R5kYkPakCBH/JykHhUwnJloQPFUpugdgWUQ79LHO4eIqT\r\nKaEQNhP+cPqwVunOT5JUIGTAzYLjIVhejg6eprWe11IGmUDDhAZIRi6Y3wUMAuyN\r\njN+rB3cHJwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAS5NBRKngXM0KUmIhfyqmF\r\nFWKpOYgp8QnjgHKi4QH6GA4AWkG6tZCzvDlMxxqUIzTuyZ8k/6qHGwdN68jPk/VD\r\nhsGm6EccvBeUvTp5w5qARbIk2fSofM394llzXAQyndyYZkDmfYMxfysdw5BLHMvD\r\nCIZtXbsjjV/OKtmgTS9BAaQJzOmwpFL1pu1VN0NbeW1M/eSx/TRD+Z80FidUe/Lp\r\nf1G1A9w4NQHf+eFSb6rCAL1WoaOi1SW1TPQOQtLdLx+yEDh56nG5MWsvznaIAJpZ\r\nWdiw8jDwBh1lWtgAVabA5okamlSct2rAYTolmd5gR7DSWtRYmb2iR5td6nQYglIA\r\n-----END CERTIFICATE-----",
  "certificate_key": "-----BEGIN RSA PRIVATE KEY-----\r\nMIIEpAIBAAKCAQEAzlHVYB7nKYj4OWX965DGTfesvv7o5Cj2rHk6kxncqqsEt5+c\r\ns/LOrqD0udNaovAjXkvCcKzuR6nfqda0DePH1KgZfn/pCT63iuj4NE8hrvtvDMIn\r\nTo9b5vNIkcHKhC0WvaAkk/LNAiujqUNubIN+iLCIFuQC03nN/UOx/k5CCiom/2TO\r\n6tluoTMyLb/vh/xqXg96jbp0vh/H9cq2SIL11tCCg73dSx7R5kYkPakCBH/JykHh\r\nUwnJloQPFUpugdgWUQ79LHO4eIqTKaEQNhP+cPqwVunOT5JUIGTAzYLjIVhejg6e\r\nprWe11IGmUDDhAZIRi6Y3wUMAuyNjN+rB3cHJwIDAQABAoIBAQDEs7xs4cmeDdoq\r\nTxThS6vklad6iOlc7bkQApxXtqZtiJL8xg3OekWWtBneOKUHB0+RDUWZyyV56Xk2\r\nIV6Uh3/zPTjhI+33RHYU17wbkv4YJ9teHJUBDyidbYDYhhwgHCS8MTvuWeQel6B3\r\nNbTHfC5c/4Ef4c7X9B7xwWKng9Dugj2UcZgSj3EuHB+yilXPIHo53pg08Ljd2Pj+\r\nC41wApS1b/1TFpYXX2OigZZc7ExIaP8/Fc9ekSh//lSysNP19+DE1Gu7HlH40kg8\r\nhoObbErq8t2D0f6x3n5j2Mw3NPe2RKELyf+zx3qmWomZhLGhg6p2gyOokf3Fdx5g\r\nu2D40HnRAoGBAPvBCSzC+UjxursJtLfoF6Zynsr26+4yd1Ww9KGlPttteEEPbqB2\r\n6Mu5mSPp/5yLnR23SNZmOdGcm7/uACr0iUyHMRhOY/NKvyiUcgaBuBnu3eVr9u9R\r\nVJrd/ZdS9nnqleYigeatwu0ZjJZN5mN6fYhj1Tq+bxmlFhKulVH7qbKlAoGBANHM\r\nob4EFahOLHBcgLkUzz/kB3Qf4NDwlq1z3IgdTfdbH+qU3bdgMomSTjBgXlKpytYP\r\nygFT8cYy7bkLhXcoJA9QldrnrGJy1L7RRRi5nKjQwS+djhQNWtZQsGcoWqz3zyZe\r\nR1sAChytqho6j8PPmEDc2Be/Q0OmDRJIyQrDvCTbAoGACEY98PSvkNAxHPiisfC0\r\n5kmaIn2fH4MVHQHl6HIv8LJWY30IW8nMuPVurRmBxzlnfpSJllJh0Bvfmp1N8Bt9\r\nb8B5wpzA+DwasFDAtqoIzQFm1aWIxjDcIQLu1MxrQXKOXrP/pP9NCtHuJvqEefyK\r\np7LwTS/5ItSkNxT532nwF+kCgYEAiERYXbn7cyjrVkPO2+f3QPFUIgm+lRdfVuPl\r\nPoeCJ4KJdW0hoUSbLp3XqTY+rYRZGbaBp2ElrW1Q2JryIlXxLf1SiC9n2T3qjtIQ\r\nBiIw7blBcTLtoHqYIJGiMi6UzrnaU3py8FlTOBNYY9bbn/xLUP3gYXQ6NUs6PEEI\r\nS7SclHcCgYB2ZWf3514NqH+401P5W3HFuzgAjXmLwlCco6tPvwvIvVSRYYch4paR\r\nKRPE9ld2jJjkboZLpfHZJlDiXTD4qCKQsjWxXLKZNtvJVgZGHSQXkGM02mQnG5Gh\r\nXHnOf1ny30ffBajlIsOvKWU1Zc4OCm6cDOKBOIkdeZP/kfJ7ZybQgA==\r\n-----END RSA PRIVATE KEY-----"
}
```

```response：
{
  "data": "",
  "msg": "Reload Success",
  "status": 200
}

:return code
200     正确返回
400     request Body 非JSON
550     表单验证失败
551     pem证书错误
552     key证书错误
553     证书存储路径未找到
554     添加证书失败
```

### 删除证书

接口：/waf/v1/cert/delete

```request:
{
  "certificate_uuid": "5bb2d573-d9ff-4a28-b14b-5ab5ec855c02"
}
```

```response：
{
  "data": "",
  "msg": "Reload Success",
  "status": 200
}

:return code
200     正确返回
400     request Body 非JSON
550     表单验证失败
554     证书删除失败
```

