python
def read_as_hex(name, size):
    addr = gdb.parse_and_eval(name).address
    data = gdb.selected_inferior().read_memory(addr, size)
    return ''.join('%02X' % ord(x) for x in data)

def read_args(name, size):
    addr = gdb.selected_frame().read_var(name)
    data = gdb.selected_inferior().read_memory(addr, size)
    return ''.join('%02X' % ord(x) for x in data)

def pm(ssl='s'):
    mk = read_as_hex('%s->session->master_key' % ssl, 48)
    cr = read_as_hex('%s->s3->client_random' % ssl, 32)
    # For TLS1.3 and later, it doesn't use premaster secret! It will use another 4 secrets: 
    # SERVER_HANDSHAKE_TRAFFIC_SECRET, CLIENT_HANDSHAKE_TRAFFIC_SECRET, SERVER_TRAFFIC_SECRET_0, CLIENT_TRAFFIC_SECRET_0
    # Here, only two of them saved in the SSL object, the two others are calculated dynamically and didn't saved in any context. So we use another method.
#    server_traffic_secret = read_as_hex('%s->server_app_traffic_secret' % ssl, 48)
#    client_traffic_secret = read_as_hex('%s->client_app_traffic_secret' % ssl, 48)
    print('CLIENT_RANDOM %s %s' % (cr, mk))
end

# This is used only for TLS1.3
def pm_tls13():
    # Since the 'secret' variable is a argument of function and it is optimized as register, 
    # it has no .address and can't use read_as_hex to get the content, use read_args instead.
    s = read_args('secret', 48)
    r = read_as_hex('ssl->s3->client_random' , 32)
    l = gdb.parse_and_eval('label').string()
    print('%s %s %s' % (l, r, s))
end

set height 0
set logging on
set logging file /home/vi/premaster.key
#set confirm off

# add this command to set breadpoint, otherwise, it will fail.
#add-symbol-file /lib64/libssl.so.1.1

# This is used for version <= TLS1.2
b ssl3_read_n
command
python pm()
c
end

# This is only valid for TLS1.3 and later
# int ssl_log_secret(SSL *ssl, const char *label, const uint8_t *secret, size_t secret_len)
b ssl_log_secret
command
python pm_tls13()
c
end

c

# command to execute: sudo gdb -p <pid> -x getOpenSSLPremasterKey.gdb --batch

# For TLS<=1.2, result is in gdb.txt, filter keys using command "grep CLIENT_RANDOM gdb.txt > premaster.key". for example output:
# CLIENT_RANDOM BC68F6EAEF4234B192D7B45787CD3ED438D0733A63525EE3A61C220701B9C3EA 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

# For TLS>=1.3, result is in gdb.txt, filter keys using command 'grep "SECRET \|SECRET_0 " gdb.txt > sslkey.txt'. for example output:
# SERVER_HANDSHAKE_TRAFFIC_SECRET F0047257736AD44F61000B7D640407DC22F42303CDF3887113AB6040F4ADDC80 1757C54D0E923BE8EBA0EE7271956E3BF56876F404D4186A4442DAB7B468648A155C2DDAD9ECF58C70CA44741B9B8A42
# EXPORTER_SECRET F0047257736AD44F61000B7D640407DC22F42303CDF3887113AB6040F4ADDC80 A8BFC814C543FFC885BACCB7090B262DDB9D97DED97322D08230007D7FFEECF66458DEE32D4240943C8C275F1D98E51A
# SERVER_TRAFFIC_SECRET_0 F0047257736AD44F61000B7D640407DC22F42303CDF3887113AB6040F4ADDC80 4AB1384F250B4428143829037CCAF70BA4D7370CDC7B08000E93C4104B5110D0B514752E1F93A5AB16786CDA4B990621
# CLIENT_HANDSHAKE_TRAFFIC_SECRET F0047257736AD44F61000B7D640407DC22F42303CDF3887113AB6040F4ADDC80 F466927B1DCE4F3FC322F691ECC805511BB82F2904FB75289400391E283334D230875FF7BA1675E4229229E2B425FB54
# CLIENT_TRAFFIC_SECRET_0 F0047257736AD44F61000B7D640407DC22F42303CDF3887113AB6040F4ADDC80 C6187F9F9AB75986C583B83C7F72CF70239E44713ED770179CE682689D14EEC7D5C98B1CF855B53E7210ACFEB5B07CFE
