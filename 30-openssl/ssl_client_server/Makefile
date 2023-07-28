
certs:
	openssl req -x509 -nodes -newkey rsa:4096 -keyout client.key -out client.crt -days 365 -subj '/CN=example.com'
	openssl req -x509 -nodes -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -subj '/CN=example.com'

clean:
	rm -f client.key client.crt
	rm -f server.key server.crt

