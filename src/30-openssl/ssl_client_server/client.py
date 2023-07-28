#!/usr/bin/env python

# Copyright 2018- The Pixie Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

import socket
import ssl
import time
import random

host_addr = '127.0.0.1'
host_port = 8082

server_sni_hostname = 'example.com'
client_cert = 'client.crt'
client_key = 'client.key'
server_cert = 'server.crt'

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=server_cert)
context.load_cert_chain(certfile=client_cert, keyfile=client_key)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn = context.wrap_socket(s, server_side=False, server_hostname=server_sni_hostname)
conn.connect((host_addr, host_port))
print("SSL established.")

count = 0
while True:
    time.sleep(1)
    secret = random.randint(0, 1024 * 1024 * 1024)
    conn.send("Client secret {} is {}".format(count, secret).encode())
    data = conn.recv(1024)
    print(data.decode())
    count += 1

print("Closing connection")
conn.close()
