upstream <UPSTREAM_TAG> {
        # server 13.7.42.92 max_fails=1 fail_timeout=10s;
        # server 13.7.42.91 max_fails=1 fail_timeout=10s;
        # server 192.168.1.158 backup;
<SERVERS>
        keepalive 10240;
}