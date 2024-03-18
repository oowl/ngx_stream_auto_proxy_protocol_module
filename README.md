# ngx_stream_auto_proxy_protocol_module
auto decode proxy_protocol information in nginx stream module

## Config
```nginx
#user  nobody;
worker_processes  1;

#error_log  logs/error.log;
#error_log  logs/error.log  notice;
#error_log  logs/error.log  info;

#pid        logs/nginx.pid;


events {
    worker_connections  1024;
}


stream {
    log_format socks 'access: $proxy_protocol_addr - $proxy_protocol_port - $proxy_protocol_server_addr - $proxy_protocol_server_port - $remote_addr - $remote_port - $proxy_protocol_port';
    server {         
        access_log logs/access.log socks;
        listen     0.0.0.0:22345;
        auto_proxy_protocol   on;
        proxy_pass cip.cc:80;
    }
}

```