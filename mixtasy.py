#!/usr/bin/env python

""" Mixtasy - an openPGP based remailer"""

import argparse
import gnupg
import hashlib
import logging
import os
import random
import string
import sys
import smtplib
import getpass

KEYSERVER = 'hkp://pgp.mit.edu'
GPG = gnupg.GPG(gpgbinary='gpg2')

PATHLENGTH = 4
FIXEDINNERSIZE = 20 * 1024
FIXEDOUTERSIZE = 30 * 1024

FORMAT = '%(asctime)s %(levelname)s %(message)s'
logging.basicConfig(format=FORMAT)
LOGGER = logging.getLogger(__name__)

def getkey(name):
    """Get a key from local keyring."""
    keys = GPG.list_keys(keys=name)
    if len(keys) == 0:
        LOGGER.info("key for name '%s' not found in local keyring", name)
        return False
    elif len(keys) > 1:
        LOGGER.info("multiple matching keys found for '%s'. Choosing first one.", name)
    return keys[0]

def encrypt_to_path(originalmessage, firstmix=None):
    """Encrypt a Message to ...
    Factory method for a wrapped message.
    """
    i = originalmessage.get_recipient().find('@')
    rdomain = originalmessage.get_recipient()[i+1:]
    rmixaddr = 'mixtasy@' + rdomain
    rmixkey = getkey(rmixaddr)
    if rmixkey == False:
        LOGGER.warning("No mix key found for the recipient FQDN: %s", rdomain)

    smixkey = False
    if firstmix != None:
        smixaddr = 'mixtasy@' + firstmix
        smixkey = getkey(smixaddr)
        if smixkey == False:
            LOGGER.warning("No mix key found for given first mix FQDN: %s", firstmix)

    path = get_path(rmixkey, smixkey)

    LOGGER.debug("Encrypt the message to the following mixes...")
    message = originalmessage
    for index, key in enumerate(path):
        i = key['uids'][0].find('<')
        address = key['uids'][0][i+1:-1]
        LOGGER.debug(address + ' ' + key['keyid'])
        # print key
        outmost_mixmessage = False
        if index == len(path)-1:
            outmost_mixmessage = True
        message = MixMessage.factory(address, message, outmost_mixmessage)

    message.pack()

    return message

def get_path(rmixkey=False, smixkey=False):
    """Generates a random path"""
    path = []
    if rmixkey != False:
        path.append(rmixkey)
    mixes = GPG.list_keys(keys='mixtasy@')
    while len(path) < PATHLENGTH:
        if smixkey != False and len(path) == PATHLENGTH - 1:
            path.append(smixkey)
        else:
            randomkey = random.SystemRandom().choice(mixes)
            if len(path) == 0 or randomkey != path[-1]:
                if smixkey == False or randomkey != smixkey:
                    path.append(randomkey)
    return path

def get_randomstring(length, chars=string.ascii_uppercase + string.digits):
    """Returns a string of random chars"""
    return ''.join(random.SystemRandom().choice(chars) for _ in range(length))

def retrieve_mixes():
    """Retrive all 'mixtasy@' keys from keyserver"""
    LOGGER.info("search key for mixtasy nodes on keyserver '%s' ...", KEYSERVER)
    keys = GPG.search_keys('mixtasy@', keyserver=KEYSERVER)
    keyids = []
    LOGGER.info("... %i keys found", len(keys))
    for key in keys:
        keyids.append(key['keyid'])
    result = GPG.recv_keys(KEYSERVER, *keyids)
    LOGGER.info("key import: %s", result.summary())

def change_openPGP_packet_lengths(data):
    """Change length of openPGP packets with tag 9 or 11
    contained in data to interdemediate length (eof)
    """
    LOGGER.log(5, "################# change_openPGP_packet_header_length")
    offset = 0
    result = str()
    while offset < len(data):
        LOGGER.log(5, "###### processing packet...")
        packetpayload = str()
        packetpayloadlength = 0
        packetsize = 1 # packet size including packet header
        packetheader = data[offset]
        offset += 1
        if not ord(packetheader) & 128 == 128:
            assert 0, 'Bad openPGP packet'
        new = ord(packetheader) & 64 == 64
        LOGGER.log(5, 'packet format: ' + ('new' if new else 'old'))
        if new:
            tag = ord(packetheader) & 63
            LOGGER.log(5, 'tag: ' + str(tag))
            packetready = False
            while not packetready:
                if ord(data[offset]) < 192:
                    # One-Octet Length
                    packetlengthheader = data[offset:offset+1]
                    offset += 1
                    length = ord(packetlengthheader[0])
                    LOGGER.log(5, "# One-Octet Length: " + str(length))
                    packetready = True
                elif ord(data[offset]) >= 192 and ord(data[offset]) < 224:
                    # Two-Octet Length
                    packetlengthheader = data[offset:offset+2]
                    offset += 2
                    length = (((ord(packetlengthheader[0]) - 192) << 8) +
                              (ord(packetlengthheader[1]) + 192))
                    LOGGER.log(5, "# Two-Octet Length: " + str(length))
                    packetready = True
                elif ord(data[offset]) == 255:
                    # Five-Octet Length
                    packetlengthheader = data[offset:offset+5]
                    offset += 5
                    length = ((ord(packetlengthheader[0]) << 24) |
                              (ord(packetlengthheader[1]) << 16) |
                              (ord(packetlengthheader[2]) << 8)  |
                              (ord(packetlengthheader[3])))
                    LOGGER.log(5, "# Five-Octet Length" + str(length))
                    packetready = True
                elif ord(data[offset]) >= 224 and ord(data[offset]) < 255:
                    # Partial Body Length
                    packetlengthheader = data[offset]
                    offset += 1
                    length = 1 << (ord(packetlengthheader[0]) & 0x1F)
                    LOGGER.log(5, "# Partial Body Length: " + str(length))
                else:
                    LOGGER.log(5, "unknown length")
                    packetready = True
                packetpayload += data[offset:offset+length]
                offset += length
                packetpayloadlength += length
                packetsize += len(packetlengthheader) + length
        else:
            tag = (ord(packetheader) & 60) >> 2
            ltype = ord(packetheader) & 3
            LOGGER.log(5, 'tag: ' + str(tag))
            LOGGER.log(5, 'ltype: ' + str(ltype))
            if ltype == 0:
                # one-octet length
                packetlengthheader = data[offset:offset+1]
                offset += 1
                length = ord(packetlengthheader[0])
                LOGGER.log(5, "# one-octet length: " + str(length))
            elif ltype == 1:
                # two-octet length
                packetlengthheader = data[offset:offset+2]
                offset += 2
                length = (ord(packetlengthheader[0]) << 8) | ord(packetlengthheader[1])
                LOGGER.log(5, "# two-octet length: " + str(length))
            elif ltype == 2:
                # four-octet length
                packetlengthheader = data[offset:offset+4]
                offset += 4
                length = ((ord(packetlengthheader[0]) << 24) |
                          (ord(packetlengthheader[1]) << 16) |
                          (ord(packetlengthheader[2]) << 8) |
                          (ord(packetlengthheader[3])))
                LOGGER.log(5, "# four-octet length: " + str(length))
            else:
                # indeterminate length
                packetlengthheader = str()
                length = len(data) - offset
                LOGGER.log(5, "# indeterminate length (until eof): " + str(length))
            packetpayload = data[offset:offset+length]
            offset += length
            packetpayloadlength = length
            packetsize += len(packetlengthheader) + length
        LOGGER.log(5, "Overall packet payload length: " + str(packetpayloadlength))
        LOGGER.log(5, "Packet size: " + str(packetsize))
        if tag == 11 or tag == 9:
            LOGGER.log(5, "alter length...")
            result += chr(128 + (tag << 2) + 3)
            result += packetpayload
        else:
            LOGGER.log(5, "keep packet...")
            result += data[offset-packetsize:offset]
    return result

class Header(object):
    """The header of an Internet Message
    ToDo: consider to use the build in email.header class
    """

    def __init__(self):
        super(Header, self).__init__()
        self.fields = {}

    def __str__(self):
        headerstring = str()
        pfields = self.fields.copy()
        if 'Verification' in pfields:
            verificationhash = pfields.pop('Verification')
            headerstring += 'Verification' + ': ' + verificationhash + '\r\n'
        for field in sorted(pfields.iterkeys()):
            headerstring += field + ': ' + self.fields[field] + '\r\n'
        return headerstring

    def set_field(self, field, value):
        """Set the field to value"""
        if isinstance(value, unicode):
            value = value.encode('UTF-8')
        self.fields[field] = value

    def get_field(self, field):
        """Get the field value"""
        if field in self.fields:
            return self.fields[field]
        else:
            return None

    def remove_field(self, field):
        """Remove the field from header"""
        return self.fields.pop(field)

    @staticmethod
    def parse_header_line(headerline):
        """Parses a header line
        returns a tupel with key and value
        """
        colonposition = headerline.find(':')
        if colonposition > 0:
            key = headerline[:colonposition]
            key = key.strip()
            if len(key) > 0:
                value = headerline[colonposition+1:]
                value = value.strip()
                return [key, value]
        return False

# class Body(str):
#     """The Body of a message"""
#     def __init__(self, body):
#         super(Body, self).__init__(body)

#     def pack(self):
#         pass

class Message(object):
    """A Internet Message"""

    def __init__(self, body):
        super(Message, self).__init__()
        self.header = Header()
        self.body = body

    def __str__(self):
        messagestring = str()
        messagestring += self.header.__str__()
        messagestring += '\r\n'
        messagestring += self.body.__str__()
        return messagestring

    def __len__(self):
        return len(self.__str__())

    def set_recipient(self, recipient):
        """Set recipient ('To' header field)"""
        self.header.set_field('To', recipient)

    def get_recipient(self):
        """Get recipient ('To' header field)"""
        return self.header.get_field('To')

    def encrypt(self):
        """encrypt the message"""
        self.body.encrypt(self.get_recipient())

    @classmethod
    def parse(cls, messagestring):
        """Parse a string as a message with header and body."""
        message = cls('')
        headerready = False
        lastheaderfield = None
        header = ''
        bodyindex = messagestring.find('\r\n\r\n')
        if bodyindex == -1:
            bodyindex = messagestring.find('\n\n')
            message.body = messagestring[bodyindex+2:]
        else:
            header = messagestring[:bodyindex]
            message.body = messagestring[bodyindex+4:]
        header = messagestring[:bodyindex]

        header = header.replace('\n ', ' ').replace('\n\t', ' ')
        for line in header.split('\n'):
            arr = Header.parse_header_line(line)
            if arr != False:
                message.header.set_field(arr[0], arr[1])
        message.body = message.body.strip()
        if isinstance(message, MixMessage):
            if 'Mixtasy-ID' in message.header.fields:
                finalmixmessage = FinalMixMessage(message.body)
                finalmixmessage.header = message.header
                message = finalmixmessage
            else:
                interdemediatemixmessage = IntermediateMixMessage(message.body)
                interdemediatemixmessage.header = message.header
                message = interdemediatemixmessage
        return message

# class OriginalMessage(Message):
#   """docstring for OriginalMessage"""

#   def __init__(self):
#       super(OriginalMessage, self).__init__()

#   def encrypt(self):
#       self.body.encrypt(self.header.get_field('To'))

#   @staticmethod
#   def parse(string):
#       m = Message.parse(string)
#       m.__class__ = OriginalMessage
#       return m

class MixMessage(Message):
    """A Mixtasy mix message"""

    def __init__(self, body):
        super(MixMessage, self).__init__(body)
        self.packed = isinstance(body, str)
        self.header.set_field('Remailer-Type', 'Mixtasy 1')

    def armor(self):
        """Armor the message body if packed"""
        if self.packed:
            binlength = len(self.body)
            result = GPG.enarmor(self.body)
            self.body = result.data
            asclength = len(self.body)
            sizeincrease = 100 / float(binlength) * float(asclength) - 100
            LOGGER.debug("Message armored, size increased by %.1f%% (from %i to %i bytes absolute)",
                         round(sizeincrease, 1), binlength, asclength)
        else:
            LOGGER.warning("Can't armor an unpacked message")

    def create_verification(self):
        """Generates the verification hash (SHA-1)"""
        verificationhash = hashlib.sha1(self.__str__()[:FIXEDINNERSIZE]).hexdigest()
        self.header.set_field('Verification', verificationhash)

    def set_type(self, mixtasytype):
        """Sets the mixtasy message type"""
        self.header.set_field('Mixtasy-Type', mixtasytype)

    def get_type(self):
        """Gets the mixtasy message type"""
        return self.header.get_field('Mixtasy-Type')

    @staticmethod
    def factory(recipient, body, outmost_mixmessage=False):
        """Factory method to create a intermediate or final mix message
        based on type of body
        """
        if isinstance(body, MixMessage):
            interdemediatemixmessage = IntermediateMixMessage(body, outmost_mixmessage)
            interdemediatemixmessage.set_recipient(recipient)
            return interdemediatemixmessage
        if isinstance(body, Message):
            finalmixmessage = FinalMixMessage(body)
            interdemediatemixmessage = IntermediateMixMessage(finalmixmessage, outmost_mixmessage)
            interdemediatemixmessage.set_recipient(recipient)
            return interdemediatemixmessage
        assert 0, 'Bad body'

    def verify(self):
        """Verifies the first 20 kbyte of the message ageinst the
        value of the verification header field
        """
        verificationfieldvalue = self.header.remove_field('Verification')
        verificationhash = hashlib.sha1(self.__str__()[:FIXEDINNERSIZE]).hexdigest()
        if verificationhash == verificationfieldvalue:
            LOGGER.info("verification ok")
            return True
        else:
            LOGGER.critical("verification failed")
        return False

class FinalMixMessage(MixMessage):
    """A Mixtasy final mix message"""

    def __init__(self, body):
        super(FinalMixMessage, self).__init__(body)
        self.set_type('singlepart')

    def pack(self):
        """Prepares the mix message for sending"""
        if not self.packed:
            result = GPG.store(
                self.body.__str__(),
                armor=False,
                compress_level=0)
            self.body = result.data
            self.generate_id()
            self.pad()
            self.create_verification()
        else:
            logging.info("Message was packed already")

    def pad(self):
        """Add the inner padding to the message"""
        # Use an openPGP packet (type: new) with tag 63 and length 0 to separate the random padding.
        # This will cause GnuPG to completely ignore everything after it and
        # the tag-63-packet itself.
        # Otherwise GnuPG may prints warnings about unexpected/mangled packets.
        self.body += '\xff\x00'
        messagelength = len(self)
        paddinglength = FIXEDINNERSIZE - messagelength
        if paddinglength < 0:
            LOGGER.error("Payload is too large for a single part message. " +
                         "Multi part messages are not implemented yet.")
            sys.exit("Payload too large")
        self.body += os.urandom(paddinglength)
        LOGGER.debug("Random padding of %i bytes added to final mix message", paddinglength)

    def generate_id(self):
        """Generates a unique Mixtasy message ID and
        set it as the 'Mixtasy-ID' header field
        """
        mixtasyid = get_randomstring(20)
        self.header.set_field('Mixtasy-ID', mixtasyid)

    def get_id(self):
        """Returns the Mixtasy-ID of this message"""
        return self.header.get_field('Mixtasy-ID')

    def unpack(self):
        """Unpacks the message body: extract the literal data packed and parses the content"""
        if self.packed:
            """Note: python-gnupg raises "Error sending data" here
            due to a broken pipe. Don't know why, decryption result is fine.
            """
            result = GPG.decrypt(self.body)
            self.body = Message.parse(result.data)
            self.packed = False
            return self.body
        else:
            logging.warning("Can't unpack unpacked message")
        return None

class IntermediateMixMessage(MixMessage):
    """A Mixtasy intermediate mix message"""

    def __init__(self, body, outmost_mixmessage=False):
        super(IntermediateMixMessage, self).__init__(body)
        self.outmost_mixmessage = outmost_mixmessage
        self.encrypted = False
        # self.set_type('intermediate')

    def pack(self):
        """Prepares the mix message for sending"""
        if not self.packed:
            self.body.pack()
            self.encrypt()
            if self.encrypted:
                self.packed = True
                if self.outmost_mixmessage:
                    self.pad()
                else:
                    self.create_verification()
        else:
            logging.info("Message was packed already")

    def encrypt(self):
        """Encrypt the body and changes the openPGP packet lengths."""
        result = GPG.store(
            self.body.__str__(),
            armor=False,
            compress_level=0)
        literaldatapacket = result.data
        literaldatapacket = change_openPGP_packet_lengths(literaldatapacket)
        result = GPG.encrypt(
            literaldatapacket,
            self.get_recipient(),
            armor=False,
            no_literal=True,
            compress_level=0,
            disable_mdc=True,
            always_trust=True)
        if result.ok:
            self.encrypted = True
            encryptedliteral = result.data
            encryptedliteral = change_openPGP_packet_lengths(encryptedliteral)
            self.body = encryptedliteral
        else:
            LOGGER.error("encryption failed: %s", result.status)

    def pad(self):
        """Pads the message body to the FIXEDOUTERSIZE"""
        if self.packed:
            messagelength = len(self.body)
            paddinglength = FIXEDOUTERSIZE - messagelength
            self.body += os.urandom(paddinglength)
            LOGGER.debug("Random padding of %i bytes added to intermediate mix message",
                         paddinglength)
        else:
            LOGGER.warning("Can't pad an unpacked message")

    def unpack(self):
        """Unpacks the message body and return the contained MixMessage"""
        if self.packed:
            result = GPG.decrypt(self.body)
            if result.ok:
                innermessage = MixMessage.parse(result.data)
                if innermessage.verify():
                    self.body = innermessage
                    if isinstance(self.body, FinalMixMessage):
                        LOGGER.info("Unpacking final mix message (id: %s)", self.body.get_id())
                        return self.body.unpack()
                    return self.body
                else:
                    LOGGER.info("Further processing of a corrupt message not allowed")
            else:
                LOGGER.error("decryption failed: %s", result.status)
        else:
            logging.warning("Can't unpack unpacked message")
        return None

def get_userinput():
    """Reads multi line input from console
    until SIGKILL (Ctrl+D) or a line with a single dot (.)
    """

    print """Type in a message.
Finish input with Ctrl+D or by enter a line containing only a . character."""

    stdinput = ''
    while 1:
        line = sys.stdin.readline()
        if line == '' or line == '.\n':
            break

        stdinput = stdinput + line
    return stdinput

def create(message, firstmix=None):
    """Create action: creates a nested mix message ready to send."""

    LOGGER.info("create a message...")

    retrieve_mixes()

    message = encrypt_to_path(message, firstmix)

    message.armor()

    return message

def unpack(message):
    """Unpack action: Decrypt an intermediate mix message and verify the payload."""

    LOGGER.info("unpack message...")
    LOGGER.info("Message is addressed to: %s", message.get_recipient())
    mixmessage = IntermediateMixMessage(message.body)
    mixmessage.header = message.header
    innermessage = mixmessage.unpack()

    if innermessage != None:
        if isinstance(innermessage, MixMessage):
            LOGGER.info("Payload is another mix message, addressed to: %s",
                        innermessage.get_recipient())
            innermessage.pad()
            innermessage.armor()
        else:
            LOGGER.info("Payload was a final mix message: original message addressed to: %s",
                        innermessage.get_recipient())
        return innermessage
    else:
        LOGGER.error("Failed to unpack message")
        sys.exit("exit due to an error")

def parse_smtp_connect_string(smtp):
    username = ''
    host = 'localhost'
    port = 587
    if '@' in smtp:
        offset = smtp.find('@')
        username = smtp[:offset]
        smtp = smtp[offset + 1:]
    if ':' in smtp:
        offset = smtp.find(':')
        host = smtp[:offset]
        port = smtp[offset + 1:]
    else:
        host = smtp
    return (username, host, port)

def send_message_smtp(message, smtp, auth, mail_from):
    LOGGER.info('Send message using SMTP')
    (host, port) = smtp
    (username, password) = auth
    server = smtplib.SMTP(host, port)
    server.ehlo_or_helo_if_needed()
    if server.has_extn('STARTTLS'):
        LOGGER.debug('Using STARTTLS')
        server.starttls()
    if username != '':
        LOGGER.debug('Authenticating')
        server.login(username, password)
    server.sendmail(mail_from, message.header.get_field('To'), message.__str__())
    server.quit()

def main():
    """Main function if executed directly (not loaded as a module)."""

    parser = argparse.ArgumentParser(description='Mixtasy - an openPGP based remailer')

    subparsers = parser.add_subparsers(
        title='Action',
        dest="action")
    # create the parser for the "create" command
    parser_create = subparsers.add_parser(
        'create',
        description='Create a mix message from a supplied email.',
        help='Create a mix message from a supplied email.')
    parser_create.add_argument(
        '-m', '--first-mix', dest='firstmix', action='store',
        nargs=1, default=None, metavar='FQDN',
        help="""FQDN of a mix used as the first one in the generated path
                (if your provider operates a mix, use that one)""")
    parser_create.add_argument(
        '-s', '--smtp', dest='smtp', action='store',
        nargs='?', const='localhost:587', default=None, metavar='username@server:port',
        help="""Send the message directly using the SMTP data provided
        with the argument value. A string in the form of [[username@]server[:port]]
        If the argument value is omitted localhost is used as the SMPT server
        with no authentication. If the SMTP server requires authentication a username
        must be given. If the port is omitted 587 will be used as default.
        If username is given it will also be used for the SMTP FROM command unless it is
        specified otherwise with -f. If neither, username or sender address is given
        LOGNAME, USER, LNAME or USERNAME will be used for the SMTP FROM command.
        Examples: alice@emailprovider.net or openrelay.net:25486""")
    parser_create.add_argument(
        '-f', '--from', dest='mail_from', action='store',
        nargs=1, default=None, metavar='sender_address',
        help="""Use the given address in the SMTP FROM command.""")
    # create the parser for the "unpack" command
    parser_unpack = subparsers.add_parser(
        'unpack',
        help='Decrypt a mix message and verify the payload.')
    # Add general arguments
    parser.add_argument('-i', '--input-file', dest='input', action='store',
                        nargs=1, default=None, metavar='file',
                        help='Read input from file instead of stdin')
    parser.add_argument('-o', '--output-file', dest='output', action='store',
                        nargs=1, default=None, metavar='file',
                        help='Write output to file instead of stdout')
    parser.add_argument(
        '-v', '--verbosity', dest='logging_verbosity', action='store',
        nargs='?', default=1, const=2, metavar='level',
        help="""Set the verbosity for logging.
        It must be between 0 and 4. Default is 1.
        0: Only critical messages;
        1: print warnings;
        2: print info messages;
        3: print debugging messages;
        4: print everything""")
    args = parser.parse_args()

    logging_verbosity = int(args.logging_verbosity)
    if logging_verbosity <= 0:
        LOGGER.setLevel(logging.CRITICAL) # 50
    elif logging_verbosity == 1:
        LOGGER.setLevel(logging.WARNING) # 30
    elif logging_verbosity == 2:
        LOGGER.setLevel(logging.INFO) # 20
    elif logging_verbosity == 3:
        LOGGER.setLevel(logging.DEBUG) # 10
    else:
        LOGGER.setLevel(1)

    userinput = None
    if args.input != None:
        messagefile = open(args.input[0], 'r')
        userinput = messagefile.read()
        messagefile.close()
    else:
        userinput = get_userinput()
    message = Message.parse(userinput)

    if args.action == 'create':
        firstmix = None
        if args.firstmix != None:
            firstmix = args.firstmix[0]
        message = create(message, firstmix)

        if args.smtp != None:
            (username, host, port) = parse_smtp_connect_string(args.smtp)
            mail_from = ''
            if args.mail_from is None:
                if username != '':
                    mail_from = username
                else:
                    mail_from = getpass.getuser()
            else:
                mail_from = args.mail_from[0]
            password = ''
            if username != '':
                password = getpass.getpass("%s's password: " % username)
            send_message_smtp(message, (host, port), (username, password), mail_from)
    elif args.action == 'unpack':
        message = unpack(message)

    output = message.__str__()
    if args.output != None:
        messagefile = open(args.output[0], 'w')
        messagefile.write(output)
        messagefile.close()
    else:
        print output

if __name__ == "__main__":
    main()
