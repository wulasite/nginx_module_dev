#!/bin/bash

cd /nginx_dev/nginx-1.16.1 && ./configure --add-module=/nginx_dev/ --prefix=/usr/local/nginx && make -j 8 && make -j 8 install && nginx -s stop && nginx -t && nginx 
