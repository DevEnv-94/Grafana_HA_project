# Grafana_HA_project

The project was created to implement Grafana High Availability with 2 Grafana instances, PostgreSQL Database for storage and Load balancer Nginx.
Prometheus,Alertmanager and exporters to monitor this ecosystem.
Entire project was automated with Ansible.


![Grafana_ha](https://github.com/DevEnv-94/Grafana_HA_project/blob/master/images/grafana_ha.png)


<details><summary>Ansible hosts file with variables (click here)</summary>
<p>

```ini
[postgres]


[postgres:vars]
ansible_user=
ansible_become=true



[grafana]


[grafana:vars]
ansible_user=
ansible_become=
gitlab_application_id=
gitlab_secret=

[nginx]


[nginx:vars]
ansible_user=
ansible_become=true 


[prometheus]


[prometheus:vars]
ansible_user=
ansible_become=
prometheus_basic_auth_login=
prometheus_basic_auth_password=
telegram_chat_id=  #How to https://stackoverflow.com/questions/32423837/telegram-bot-how-to-get-a-group-chat-id/38388851#38388851
telegram_bot_token=
deadmanssnitch_url= #how to [https://deadmanssnitch.com/docs]


[all:children]
nginx
grafana
postgres
prometheus

[postgres_pass:children]
grafana
postgres

[postgres_pass:vars]
postgres_password=

[domain:children]
nginx
grafana
prometheus

[domain:vars]
domain= # without www. part

[all:vars]
ansible_ssh_private_key_file=
```

</p>
</details>

## Nginx wtih TLS termination and exporter

Nginx Docker-Compose file
```yaml
version: "3.7"


networks:
  nginx_network:

volumes:
  nginx-logs:

services:
  nginx:
    build: .
    restart: unless-stopped
    networks:
      - nginx_network
    ports:
        - 80:80
        - 443:443
    expose:
      - "8080"
    volumes:
      - ./dhparam:/etc/nginx/dhparam
      - ./default.conf:/etc/nginx/conf.d/default.conf
      - /etc/letsencrypt:/etc/letsencrypt
      - ./www:/var/www
      - nginx-logs:/var/log/nginx/


  nginx_exporter:
    image: sophos/nginx-vts-exporter:v0.10.7
    restart: unless-stopped
    networks:
      - nginx_network
    ports:
        - {{ansible_eth1.ipv4.address}}:9913:9913
    environment:
      NGINX_STATUS: "http://nginx:8080/status/format/json"
```

<details><summary>Nginx Dockerfile with traffic status module (click here)</summary>
<p>

Dokckerfile
```Dockerfile
ARG version=1.22.0

FROM nginx:${version}-alpine AS builder

ARG version

WORKDIR /root/

RUN apk add --update --no-cache build-base git pcre-dev openssl-dev zlib-dev linux-headers \
    && wget http://nginx.org/download/nginx-${version}.tar.gz \
    && tar zxf nginx-${version}.tar.gz \
    && git clone https://github.com/vozlt/nginx-module-vts.git \
    && cd nginx-module-vts \
    && git submodule update --init --recursive \
    && cd ../nginx-${version} \
    && ./configure \
    --add-dynamic-module=../nginx-module-vts \
    --prefix=/etc/nginx \
    --sbin-path=/usr/sbin/nginx \
    --modules-path=/usr/lib/nginx/modules \
    --conf-path=/etc/nginx/nginx.conf \
    --error-log-path=/var/log/nginx/error.log \
    --http-log-path=/var/log/nginx/access.log \
    --pid-path=/var/run/nginx.pid \
    --lock-path=/var/run/nginx.lock \
    --http-client-body-temp-path=/var/cache/nginx/client_temp \
    --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
    --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
    --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
    --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
    --with-perl_modules_path=/usr/lib/perl5/vendor_perl \
    --user=nginx \
    --group=nginx \
    --with-compat \
    --with-file-aio \
    --with-threads \
    --with-http_addition_module \
    --with-http_auth_request_module \
    --with-http_dav_module \
    --with-http_flv_module \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_random_index_module \
    --with-http_realip_module \
    --with-http_secure_link_module \
    --with-http_slice_module \
    --with-http_ssl_module \
    --with-http_stub_status_module \
    --with-http_sub_module \
    --with-http_v2_module \
    --with-mail \
    --with-mail_ssl_module \
    --with-stream \
    --with-stream_realip_module \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
    --with-cc-opt='-Os -fomit-frame-pointer -g' \
    --with-ld-opt=-Wl,--as-needed,-O1,--sort-common \
    && make modules

FROM nginx:${version}-alpine

ARG version

RUN sed -i '1iload_module modules/ngx_http_vhost_traffic_status_module.so;' /etc/nginx/nginx.conf

COPY --from=builder /root/nginx-${version}/objs/ngx_http_vhost_traffic_status_module.so /usr/lib/nginx/modules/
```

</p>
</details>


<details><summary>Nginx Grafana site config file (click here)</summary>
<p>

```bash
log_format logs       '$remote_addr - $remote_user [$time_local] '
                      '"$request" $status $body_bytes_sent '
                      '"$http_referer" "$http_user_agent"';


vhost_traffic_status_zone;
server {

 listen 8080;
 access_log /var/log/nginx/access.log logs;  

 location / {
 }

 location /status {
   vhost_traffic_status_display;
   vhost_traffic_status_display_format html; 
 }


}

server {
	listen 80 ;

	root /var/www/;

	index index.html index.htm index.nginx-debian.html;

	server_name {{domain}} www.{{domain}};

  access_log /var/log/nginx/access.log logs;

  if ($host !~ ^({{domain}}|www.{{domain}})$ ) {
      return 444;
  }

	location / {
	  return 301 https://$host$request_uri;
	}

}


upstream grafana {
  server {{ hostvars[groups['grafana'][0]]['ansible_eth1']['ipv4']['address'] }}:3000;
  server {{ hostvars[groups['grafana'][1]]['ansible_eth1']['ipv4']['address'] }}:3000;
}

server {
    listen 443 ssl http2 default_server;

    access_log /var/log/nginx/access.log logs;

    index index.html index.htm ;

    ssl_certificate /etc/letsencrypt/live/{{domain}}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{{domain}}/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:MozSSL:10m;  # about 40000 sessions
    ssl_session_tickets off;

    # curl https://ssl-config.mozilla.org/ffdhe2048.txt > /path/to/dhparam
    ssl_dhparam /etc/nginx/dhparam;


    # intermediate configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # HSTS (ngx_http_headers_module is required) (63072000 seconds)
    add_header Strict-Transport-Security "max-age=63072000" always;

    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;

    # verify chain of trust of OCSP response using Root CA and Intermediate certs
    ssl_trusted_certificate /etc/letsencrypt/live/{{domain}}/fullchain.pem;

    # replace with the IP address of your resolver
    resolver 8.8.8.8;


    if ($host !~ ^({{domain}}|www.{{domain}})$ ) {
        return 444;
    }

    location / {
        proxy_pass http://grafana;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Host $server_name;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
      }

    location ~ /.well-known/acme-challenge/ {
        root /var/www/;
    }

}
```
</p>
</details>

## Grafana with GitLab authentication and Grafana-image-renderer

Grafana Docker-Compose file
```yaml
version: "3.7"

networks:
  grafana_network:

services:
  grafana:
    image: grafana/grafana-oss:9.0.1
    restart: unless-stopped
    networks:
      - grafana_network
    ports:
        - {{ansible_eth1.ipv4.address}}:3000:3000
    env_file: ./.env
      
  renderer:
    image: grafana/grafana-image-renderer:3.6.1
    restart: unless-stopped
    networks:
      - grafana_network
    expose:
      - 8081
```

<details><summary>grafana environment file (click here)</summary>
<p>

```bash
GF_SERVER_DOMAIN={{ domain }}
GF_SERVER_ROOT_URL=https://{{ domain }}/
GF_METRICS_ENABLED=true
GF_METRICS_DISABLE_TOTAL_STATS=false
GF_DATABASE_TYPE=postgres
GF_DATABASE_HOST={{ hostvars[groups['postgres'][0]]['ansible_eth1']['ipv4']['address'] }}:5432
GF_DATABASE_NAME=grafana
GF_DATABASE_USER=postgres
GF_DATABASE_PASSWORD={{ postgres_password }}
GF_DATABASE_SSL_MODE=disable
GF_AUTH_GITLAB_ENABLED=true
GF_AUTH_GITLAB_ALLOW_SIGN_UP=false
GF_AUTH_GITLAB_CLIENT_ID={{ gitlab_application_id }}
GF_AUTH_GITLAB_CLIENT_SECRET={{ gitlab_secret }}
GF_AUTH_GITLAB_SCOPES=read_api
GF_AUTH_GITLAB_AUTH_URL=https://gitlab.com/oauth/authorize
GF_AUTH_GITLAB_TOKEN_URL=https://gitlab.com/oauth/token
GF_AUTH_GITLAB_API_URL=https://gitlab.com/api/v4
GF_RENDERING_SERVER_URL=http://renderer:8081/render
GF_RENDERING_CALLBACK_URL=http://grafana:3000/
GF_LOG_FILTERS=rendering:debug
```
</p>
</details>

## Postgres Database and exporter

Postgres Docker-Compose file
```yaml
version: "3.7"


networks:
  postgres_network:

volumes:
  postgresql-data:

services:
  postgres:
    image: postgres:14.5
    restart: unless-stopped
    ports:
        - {{ansible_eth1.ipv4.address}}:5432:5432
    volumes:
        - postgresql-data:/var/lib/postgresql/data
    env_file: 
        - ./.env


  postgres_exporter:
    image: prometheuscommunity/postgres-exporter:v0.11.1
    restart: unless-stopped
    ports:
        - {{ansible_eth1.ipv4.address}}:9187:9187
    environment:
      DATA_SOURCE_NAME: "postgresql://postgres:{{ postgres_password }}@postgres:5432/postgres?sslmode=disable"
```

</p>
</details>

<details><summary>Postgres environment file (click here)</summary>
<p>

```bash
POSTGRES_DB=grafana
POSTGRES_USER=postgres
POSTGRES_PASSWORD={{ postgres_password }}
```

</p>
</details>

## Prometheus, Alertmanager, Rules and Alerts in Telegram and DeadManSnitch

Prometheus and Alertmanager Docker-Compose file
```yaml
version: "3.7"

networks:
  prometheus_network:

volumes:
  prometheus-data:
  alertmanager-data:

services:
  prometheus:
    image: prom/prometheus:v2.36.2
    networks:
      - prometheus_network
    restart: unless-stopped
    ports:
      - {{ansible_eth1.ipv4.address}}:9090:9090
    volumes:
      - /opt/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
      - /opt/prometheus/web.yml:/etc/prometheus/web.yml
      - /opt/prometheus/prometheus.key:/etc/prometheus/prometheus.key
      - /opt/prometheus/prometheus.crt:/etc/prometheus/prometheus.crt
      - /opt/prometheus/rules:/etc/prometheus/rules
      - prometheus-data:/prometheus
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
      - "--storage.tsdb.path=/prometheus" 
      - "--web.console.libraries=/usr/share/prometheus/console_libraries" 
      - "--web.console.templates=/usr/share/prometheus/consoles"
      - "--web.config.file=/etc/prometheus/web.yml"


  alertmanager:
    image: bitnami/alertmanager:0.24.0
    networks:
      - prometheus_network
    restart: unless-stopped
    expose:
      - 9093
    volumes:
      - "/opt/prometheus/alertmanager:/etc/alertmanager"
      - alertmanager-data:/data
    command: --config.file=/etc/alertmanager/alertmanager.yml --log.level=debug
```

<details><summary>Prometheus config file (click here)</summary>
<p>

```yaml
---

global:
  scrape_interval:     5s
  evaluation_interval: 5s
  scrape_timeout: 5s

rule_files:
  - "rules/*.yml"

alerting:
  alertmanagers:
    - static_configs:
      - targets: ['alertmanager:9093']

scrape_configs:
  - job_name: 'prometheus'
    scheme: https
    basic_auth:
      username: "{{ prometheus_basic_auth_login }}"
      password: "{{ prometheus_basic_auth_password }}"
    tls_config:
      insecure_skip_verify: true
      ca_file: /etc/prometheus/prometheus.crt
    static_configs:
      - targets: ['{{ansible_eth1.ipv4.address}}:9090']

  - job_name: 'prom_node_ex'
    static_configs:
      - targets: ['{{ansible_eth1.ipv4.address}}:9100']


  - job_name: 'nginx_node_ex'
    static_configs:
      - targets: ['{{ hostvars[groups['nginx'][0]]['ansible_eth1']['ipv4']['address'] }}:9100']

  - job_name: 'nginx_exporter'
    static_configs:
      - targets: ['{{ hostvars[groups['nginx'][0]]['ansible_eth1']['ipv4']['address'] }}:9913']


  - job_name: 'grafana_1_node_ex'
    static_configs:
      - targets: ['{{ hostvars[groups['grafana'][0]]['ansible_eth1']['ipv4']['address'] }}:9100']

  - job_name: 'grafana_1_metrics'
    static_configs:
      - targets: ['{{ hostvars[groups['grafana'][0]]['ansible_eth1']['ipv4']['address'] }}:3000']


  - job_name: 'grafana_2_node_ex'
    static_configs:
      - targets: ['{{ hostvars[groups['grafana'][1]]['ansible_eth1']['ipv4']['address'] }}:9100']

  - job_name: 'grafana_2_metrics'
    static_configs:
      - targets: ['{{ hostvars[groups['grafana'][1]]['ansible_eth1']['ipv4']['address'] }}:3000']


  - job_name: 'postgres_node_ex'
    static_configs:
      - targets: ['{{ hostvars[groups['postgres'][0]]['ansible_eth1']['ipv4']['address'] }}:9100']

  - job_name: 'postgres_ex'
    static_configs:
      - targets: ['{{ hostvars[groups['postgres'][0]]['ansible_eth1']['ipv4']['address'] }}:9187']
```

</p>
</details>

<details><summary>Alertmanager config file (click here)</summary>
<p>

```yaml
route:
  group_by: ['alertname']
  group_wait: 60s
  group_interval: 5m
  repeat_interval: 30m
  receiver: 'telegram' # basic reciever, if alert doesn't match any matchers this reciever gets alert.
  routes:
  - receiver: 'telegram' 
    matchers:
    - severity=~"critical|warning" 
    
  - receiver: 'DeadMansSnitch'
    repeat_interval: 1m
    group_wait: 0s
    matchers:
    - severity="none"


receivers: 
- name: 'DeadMansSnitch'
  webhook_configs:
  - url: {{ deadmanssnitch_url }} #how to [https://deadmanssnitch.com/docs]
    send_resolved: false
- name: 'telegram'  
  telegram_configs:
    - send_resolved: true
      api_url: "https://api.telegram.org"
      bot_token: "{{ telegram_bot_token }}"
      chat_id: {{ telegram_chat_id }}
      parse_mode: "HTML"


inhibit_rules:
  - source_matchers:
    - severity="critical"
    target_matchers:
    - severity="warning"
    equal: ['instance']
```
</p>
</details>

### Rules

![rules](https://github.com/DevEnv-94/Grafana_HA_project/blob/master/images/rules.png)

* Rules for [nginx](https://github.com/DevEnv-94/Grafana_HA_project/blob/master/prometheus/templates/nginx_rules.yml.j2).

* Rules for [grafana](https://github.com/DevEnv-94/Grafana_HA_project/blob/master/prometheus/files/grafana_rules.yml).

* Rules for [postgres](https://github.com/DevEnv-94/Grafana_HA_project/blob/master/prometheus/files/postgres_rules.yml).

* Rules for [prometheus](https://github.com/DevEnv-94/Grafana_HA_project/blob/master/prometheus/files/prom_rules.yml).

### Alerts

Telegram Alerts
![telegram_alerts](https://github.com/DevEnv-94/Grafana_HA_project/blob/master/images/telegram_alerts.png)


DeadManSnitch
This is reciever created for All prometheus monitoring system, always firing and sends signal every minute, when prometheus is dead or some trouble with alertmanager, stops sending signal and you recieve alert.

```yaml
  - alert: PrometheusAlertmanagerE2eDeadManSwitch
    expr: vector(1)
    for: 0m
    labels:
      severity: none
    annotations:
      summary: Prometheus AlertManager E2E dead man switch (instance {{ $labels.instance }})
      description: "Prometheus DeadManSwitch is an always-firing alert. It's used as an end-to-end test of Prometheus through the Alertmanager.\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"
```

This rule have to be always firing.

![deadmansnitch](https://github.com/DevEnv-94/Grafana_HA_project/blob/master/images/deadmansnitch.png)
![deadmansnitch2](https://github.com/DevEnv-94/Grafana_HA_project/blob/master/images/deadmansnitch2.png)



DeadMansnitch Alert
![deadmansnitch_alert](https://github.com/DevEnv-94/Grafana_HA_project/blob/master/images/deadmansnitch_alert.png)


## Grafana Dasboard

Created one Dasboard with four sections : Grafana, Nginx, Postgres, Prometheus.

Grafana
![grafana](https://github.com/DevEnv-94/Grafana_HA_project/blob/master/images/grafana.png)

Nginx
![nginx](https://github.com/DevEnv-94/Grafana_HA_project/blob/master/images/nginx.png)

Postgres
![postgres](https://github.com/DevEnv-94/Grafana_HA_project/blob/master/images/postgres.png)

Prometheus
![prometheus](https://github.com/DevEnv-94/Grafana_HA_project/blob/master/images/prometheus.png)
