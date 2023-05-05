python
def read_as_hex(name, size):
    addr = gdb.parse_and_eval(name).address
    data = gdb.selected_inferior().read_memory(addr, size)
    return ''.join('%02X' % ord(x) for x in data)

def pm(ssl='s'):
    mk = read_as_hex('%s->session->master_key' % ssl, 48)
    cr = read_as_hex('%s->s3->client_random' % ssl, 32)
    print('CLIENT_RANDOM %s %s' % (cr, mk))
end

set logging on
set logging file /home/vi/premaster.key

b ssl3_read_n
command
python pm()
c
end

c

# command to execute: sudo gdb -p <pid> -x getOpenSSLPremasterKey.gdb --batch
# result is in gdb.txt, filter keys using command "grep CLIENT_RANDOM gdb.txt > premaster.key". for example output:
# CLIENT_RANDOM BC68F6EAEF4234B192D7B45787CD3ED438D0733A63525EE3A61C220701B9C3EA 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
