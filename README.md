# wireray

wireray is a tool for packet capture and HTTP logging / profiling.

:warning: v0.1.0 is still unstable :warning:

## Requirements

- libpcap
    - `apt-get install libpcap-dev`
    - `yum install libpcap-devel`

## Installation

Download from https://github.com/tkuchiki/wireray/releases

## :warning: Known Issues :warning:

- https://github.com/google/gopacket/issues/253  

## Usage

### logging

- `->` = HTTP Request
- `<-` = HTTP Response
- `[XXX: xxx]` = HTTP Header

```console
# terminal 1
$ sudo wireray logging --port=8080
Password:
2019/08/21 01:43:57 Using BPF filter "tcp and port 8080"
2019/08/21 01:43:57 Starting to read packets
-> 2019-08-21T01:44:11.298685 GET / 0 bytes [User-Agent: curl/7.54.0] [Accept: */*]
<- 2019-08-21T01:44:11.298749 GET / 612 bytes 200 0.000063 sec [Server: nginx/1.17.3] [Last-Modified: Tue, 13 Aug 2019 12:46:01 GMT] [Etag: "5d52b109-264"] [Date: Tue, 20 Aug 2019 16:44:11 GMT] [Content-Type: text/html] [Content-Length: 612] [Connection: keep-alive] [Accept-Ranges: bytes]

# terminal 2
$ curl -s localhost:8080 > /dev/null 
```

```console
# terminal 1
$ sudo wireray logging --port=8080 --body
2019/08/21 01:52:49 Using BPF filter "tcp and port 8080"
2019/08/21 01:52:49 Starting to read packets
-> 2019-08-21T01:52:52.024304 GET / 14 bytes [User-Agent: curl/7.54.0] [Content-Type: application/x-www-form-urlencoded] [Content-Length: 14] [Accept: */*]
{"foo": "bar"}
<- 2019-08-21T01:52:52.024399 GET / 16 bytes 200 0.000096 sec [Server: nginx/1.17.3] [Date: Tue, 20 Aug 2019 16:52:52 GMT] [Content-Type: application/octet-stream] [Content-Length: 16] [Connection: keep-alive]
{"status": "ok"}

# terminal 2
$ curl -X GET --data '{"foo": "bar"}' -s localhost:8080 > /dev/null
```

```console
# terminal 1
$ sudo wireray logging --port=8080 --body
2019/08/21 02:12:42 Using BPF filter "tcp and port 8080"
2019/08/21 02:12:42 Starting to read packets
-> 2019-08-21T02:12:46.304129 GET / 0 bytes [User-Agent: curl/7.54.0] [Content-Type: application/json] [Accept-Encoding: gzip] [Accept: */*]
<- 2019-08-21T02:12:46.304174 GET / 36 bytes 200 0.000045 sec [Server: nginx/1.17.3] [Date: Tue, 20 Aug 2019 17:12:46 GMT] [Content-Type: application/json] [Content-Encoding: gzip] [Connection: keep-alive]
V*.I,)-VRPVh$

# terminal 2
$ curl -H "Content-Type: application/json" -H "Accept-Encoding: gzip" -s localhost:8080 > /dev/null
```

```console
# terminal 1
$ sudo wireray logging --port=8080 --body --gunzip
2019/08/21 02:14:03 Using BPF filter "tcp and port 8080"
2019/08/21 02:14:03 Starting to read packets
-> 2019-08-21T02:14:09.675096 GET / 0 bytes [User-Agent: curl/7.54.0] [Content-Type: application/json] [Accept-Encoding: gzip] [Accept: */*]
<- 2019-08-21T02:14:09.675165 GET / 16 bytes 200 0.000069 sec [Server: nginx/1.17.3] [Date: Tue, 20 Aug 2019 17:14:09 GMT] [Content-Type: application/json] [Content-Encoding: gzip] [Connection: keep-alive]
{"status": "ok"}

# terminal 2
$ curl -H "Content-Type: application/json" -H "Accept-Encoding: gzip" -s localhost:8080 > /dev/null
```

### profiling

Works like [alp](https://github.com/tkuchiki/alp).

```console
# terminal 1
$ sudo wireray profiling --port=8080
2019/08/21 02:15:39 Using BPF filter "tcp and port 8080"
2019/08/21 02:15:39 Starting to read packets
^C2019/08/21 02:15:55 Stopping to read packets
+-------+-----+-----+-----+-----+-----+--------+-----+-------+-------+-------+-------+-------+-------+-------+--------+-----------+-----------+-----------+-----------+
| COUNT | 1XX | 2XX | 3XX | 4XX | 5XX | METHOD | URI |  MIN  |  MAX  |  SUM  |  AVG  |  P1   |  P50  |  P99  | STDDEV | MIN(BODY) | MAX(BODY) | SUM(BODY) | AVG(BODY) |
+-------+-----+-----+-----+-----+-----+--------+-----+-------+-------+-------+-------+-------+-------+-------+--------+-----------+-----------+-----------+-----------+
|     2 |   0 |   2 |   0 |   0 |   0 | GET    | /   | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |  0.000 |    16.000 |    36.000 |    52.000 |    26.000 |
+-------+-----+-----+-----+-----+-----+--------+-----+-------+-------+-------+-------+-------+-------+-------+--------+-----------+-----------+-----------+-----------+

# terminal 2
$ curl -H "Content-Type: application/json" -H "Accept-Encoding: gzip" -s localhost:8080 > /dev/null
Exec: 0.032 sec

$ curl -s localhost:8080 > /dev/null
```