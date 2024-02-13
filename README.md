Simple script to enrich iptables journald output with geolocation data acquired from ipinfo.io API to use in Grafana Geomap plugin.

Based on bossm8 idea but does not require docker or syslog-ng: https://medium.com/@bossm8/geoip-dashboards-in-grafana-from-iptables-logs-101a3b256d55

Dependencies:

    pip install pycountry, geohash2, conson

Usage:

    nohup python3 geoip2grafana.py &
(or you can create .service file)

You can set paths to log directory and tempfile directory in geoip2grafana_config.json file. You HAVE TO add your own ipinfo.io token to this config.
Also, IP address by default will be queried in API every 72 hours (.temp file stores dictionary of IP:timestamp), you can change that value in config using datetime timedelta syntax:

    minutes=float
    hours=float
    days=float
    weeks=float


Requires iptables journald logging:

     iptables -N IP_LOGGING
     iptables -A IP_LOGGING -s 10.0.0.0/8,172.16.0.0/12,192.168.178.0/24,127.0.0.1/32 -j RETURN    # put any private ip pool you do NOT want to log
     iptables -A IP_LOGGING -m recent --rcheck --seconds 43200 --name iptrack --rsource -j RETURN
     iptables -A IP_LOGGING -m recent --set --name iptrack --rsource
     iptables -A IP_LOGGING -j LOG --log-prefix "[iptables] "
     iptables -A INPUT -j IP_LOGGING

Promtail job:

    - job_name: some_job
    static_configs:
    - targets:
        - localhost
      labels:
        job: some_job_label
        __path__: /var/log/geoip2grafana.log
    pipeline_stages:
      - json:
        expressions:
          geoip_country_name: geoip.country.names.en
          geoip_city_name: geoip.city.en
          geoip_geohash: geoip.location.geohash
          geoip_asn: geoip.organization.AS
          geoip_org: geoip.organization.name
    - labels:
        geoip_country_name: geoip_country_name
        geoip_city_name: geoip_city_name
        geoip_geohash: geoip_geohash
        geoip_asn: geoip_asn
        geoip_org: geoip_org
        src_port: ipt.SPT
        dst_port: ipt.DPT
        protocol: ipt.PROTO
    - output:
        source: message

  By default, script will collect from iptables journald log entries following items:

    "IN" - inbound interface
    "SRC" - source IP
    "OUT" - outbound interface
    "SPT" - source port,
    "PROTO" - protocol,
    "DST" - destination IP
    "DPT" - destination port
    
  You can freely add in config file whatever you want to pass to grafana from iptables log. Just remember to put it in promtail job config label.
