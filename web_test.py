#!/bin/python
# -*- coding: UTF-8 -*-
# 文件名：server.py
# create by wzh 2017/10/26
import subprocess
import socket
import re
from multiprocessing import Process
import datetime
import os
import signal
from pathlib import Path

def handle_client(client_socket):
    print("client_socket",client_socket)
    request_data = client_socket.recv(1024)
    # print(request_data)
    request_lines = request_data.splitlines()
    # for line in request_lines:
    #     print(line)
    request_start_line = request_lines[0].decode("utf-8")
    # print("*" * 10)
    # print(request_start_line)
    content = porttest()
    response_start_line = "HTTP/1.1 200 ok\r\n"
    response_heads = "Server: My server\r\n"
    response_body = "*" * 20 + "*" * 20 + "\n" + content
    response = response_start_line + response_heads + "\r\n" + response_body
    # print("response data:", response)
    # client_socket.send(bytes(response, "utf-8"))
    client_socket.send(response.encode("utf-8"))
    client_socket.close()
    count = 0
    for i in content.split("\n"):
        if i.endswith("succeeded!"):
            count += 1
    print(count)
    if count == 37 or count == 40:
        os.kill(os.getppid(), signal.SIGTERM)


def porttest():
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
    results = '----------------%s----------------\n'%timestamp
    # dckit.apple.com : 443
    dckit_IPs= ['17.188.23.205','17.188.23.154','17.188.23.178'] #443
    dckit_asset = ['17.188.23.205','17.188.23.178', '17.188.23.154'] # 80 and 443
    # narrative.apple.com : 443
    narrative_IPs = ['17.32.202.100','17.32.202.135','17.122.46.104'] #443
    #updates-http.g.aaplimg.com	: 443
    update_http_IPs=['17.253.17.206', '17.253.17.207', '17.253.17.208']#80 & 443
    #gdmf.apple.com: 80/443
    gdmf_IPs = ['17.137.162.3'] #443
    #gs.apple.com: 80/443
    gs_IPs = ['17.137.162.1', '17.171.47.65', '17.171.47.17'] #80 & 443
    #gg.apple.com : 80/443
    gg_IPs = ['17.111.103.69'] #80 & 443
    for IPs in dckit_IPs, narrative_IPs, gdmf_IPs:
        for ip in IPs:
            results += check_port(ip, 443)
        # Test 443, 80 ports
    for IPs in update_http_IPs, gs_IPs, gg_IPs, dckit_asset:
        for ip in IPs:
            results += check_port(ip, 443)
            results += check_port(ip, 80)
    return results


def save_networkres(result, filename):
    with open(filename, "w") as f:
        f.write(result)


def check_port(ip, port=80):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((ip, port))
        s.shutdown(2)
        result = 'connect to %s:%d is succeeded!\n' % (ip, port)
        return result
    except socket.error:
        result = 'connect to %s:%d is failed!\n' % (ip, port)
        return result


def kill_self(signum, frame):
    print(signum)
    print(os.getpid())
    os.kill(os.getpid(), signal.SIGTERM)


if __name__ == "__main__":
   '''
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    port = 1212
    s.bind(("", port))
    s.listen(5)
    signal.signal(signal.SIGALRM, kill_self)
    signal.alarm(1209600)
    while True:
        c, addr = s.accept()
        print('连接地址', addr)
        handle_client_process = Process(target=handle_client, args=(c,))
        handle_client_process.start()
        c.close()
   '''
   srcip = input("Input testing sourceip:")
   filename =  str(Path.home()) + "/" + srcip  + ".txt"
   print(filename)
   result = porttest()
   save_networkres(result, filename)
