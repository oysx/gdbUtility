python
def read_as_hex(name, size):
    addr = gdb.parse_and_eval(name).address
    data = gdb.selected_inferior().read_memory(addr, size)
    return ''.join('%02X' % ord(x) for x in data)

def pm(ssl='s'):
    mk = read_as_hex('%s->session->master_key' % ssl, 48)
    cr = read_as_hex('%s->s3->client_random' % ssl, 32)
    #For TLS1.3, it doesn't use premaster secret! It will use another 4 secrets: 
    # SERVER_HANDSHAKE_TRAFFIC_SECRET, CLIENT_HANDSHAKE_TRAFFIC_SECRET, SERVER_TRAFFIC_SECRET_0, CLIENT_TRAFFIC_SECRET_0
    #Here, I can only find two of them, TODO: find out another 2 secrets
#    server_traffic_secret = read_as_hex('%s->server_app_traffic_secret' % ssl, 48)
#    client_traffic_secret = read_as_hex('%s->client_app_traffic_secret' % ssl, 48)
    print('CLIENT_RANDOM %s %s' % (cr, mk))
end

set height 0
set logging on
set logging file /home/vi/premaster.key
#set confirm off

# add this command to set breadpoint, otherwise, it will fail.
#add-symbol-file /lib64/libssl.so.1.1

b ssl3_read_n
command
python pm()
c
end

c

# command to execute: sudo gdb -p <pid> -x getOpenSSLPremasterKey.gdb --batch
# result is in gdb.txt, filter keys using command "grep CLIENT_RANDOM gdb.txt > premaster.key". for example output:
# CLIENT_RANDOM BC68F6EAEF4234B192D7B45787CD3ED438D0733A63525EE3A61C220701B9C3EA 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
