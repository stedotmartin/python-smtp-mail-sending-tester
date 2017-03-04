#!/usr/bin/python
"""smtptest.py: command-line smtp test mail sender
https://github.com/turbodog/python-smtp-mail-sending-tester

Usage: python smtptest.py [options] fromaddress toaddress serveraddress

Examples:
	python smtptest.py bob@example.com mary@example.com mail.example.com
	python smtptest.py --debuglevel 1 --usetls -u bob -p xyzzy "Bob <bob@example.com>" mary@example.com mail.example.com

At verbose == False and debuglevel == 0, smtptest will either succeed silently or print an error. Setting verbose or a debuglevel to 1 will generate intermediate output.

See also http://docs.python.org/library/smtplib.html

"""

__version__ = "1.0"
__author__ = "Lindsey Smith (lindsey.smith@gmail.com)"
__copyright__ = "(C) 2010 Lindsey Smith. GNU GPL 2 or 3."

import smtplib
from time import strftime
import sys
from optparse import OptionParser

from os.path import basename
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate


def send_mail(send_from, send_to, subject, text, file=None, server="127.0.0.1", port=25, ssl=False, tls=False, debuglevel=None):

    msg = MIMEMultipart()
    msg['From'] = send_from
    msg['To'] = COMMASPACE.join(send_to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject
    msg.attach(MIMEText(text))
    if file:
        with open(file, "rb") as f:
            part = MIMEApplication(
                f.read(),
                Name=basename(file)
            )
            part['Content-Disposition'] = 'attachment; filename="%s"' % basename(file)
            msg.attach(part)
    smtp = None
    if ssl:
        smtp = smtplib.SMTP_SSL()
    else:
        smtp = smtplib.SMTP()
    smtp.set_debuglevel(debuglevel)
    smtp.connect(server, port)
    smtp.ehlo()
    if tls: smtp.starttls()
    if options.SMTP_USER != "": smtp.login(options.SMTP_USER, options.SMTP_PASS)
    smtp.sendmail(send_from, send_to, msg.as_string())
    smtp.close()

usage = "Usage: %prog [options] fromaddress toaddress serveraddress"
parser = OptionParser(usage=usage)

parser.set_defaults(usetls=False)
parser.set_defaults(usessl=False)
parser.set_defaults(serverport=25)
parser.set_defaults(SMTP_USER="")
parser.set_defaults(SMTP_PASS="")
parser.set_defaults(debuglevel=0)
parser.set_defaults(verbose=False)

parser.add_option("-a", "--attach", action="store", dest="attach", default=None,
                  help="Attach a file, default is None")
parser.add_option("-S", "--spam", action="store_true", dest="spam", default=False,
                  help="Use GTUBE code to trigger spam filter positive, default is false")
parser.add_option("-V", "--virus", action="store_true", dest="virus", default=False,
                  help="Use eicar code to trigger virus scanner  positive, default is false")
parser.add_option("-t", "--usetls", action="store_true", dest="usetls", default=False,
                  help="Connect using TLS, default is false")
parser.add_option("-s", "--usessl", action="store_true", dest="usessl", default=False,
                  help="Connect using SSL, default is false")
parser.add_option("-n", "--port", action="store", type="int", dest="serverport", help="SMTP server port", metavar="nnn")
parser.add_option("-u", "--username", action="store", type="string", dest="SMTP_USER", help="SMTP server auth username",
                  metavar="username")
parser.add_option("-p", "--password", action="store", type="string", dest="SMTP_PASS", help="SMTP server auth password",
                  metavar="password")
parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False,
                  help="Verbose message printing")
parser.add_option("-d", "--debuglevel", type="int", dest="debuglevel", help="Set to 1 to print smtplib.send messages",
                  metavar="n")

(options, args) = parser.parse_args()
if len(args) != 3:
    parser.print_help()
    parser.error("incorrect number of arguments")
    sys.exit(-1)

fromaddr = args[0]
toaddr = args[1]
serveraddr = args[2]

now = strftime("%Y-%m-%d %H:%M:%S")

subject = "Test message"
msg = "Test message from the smtptest tool sent at %s" % (now)
spam = """This is the GTUBE, the
	Generic
	Test for
	Unsolicited
	Bulk
	Email

If your spam filter supports it, the GTUBE provides a test by which you
can verify that the filter is installed correctly and is detecting incoming
spam. You can send yourself a test mail containing the following string of
characters (in upper case and with no white spaces and line breaks):

XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X

You should send this test mail from an account outside of your network.

"""
if options.spam:
    msg = msg + '\n\n'
    msg = msg + 'Adding the GTUBE test signature for positive SPAM detection'
    msg = msg + '\n\n'
    msg = msg + spam
    subject = subject + ' SPAM:True'

if options.virus:
    msg = msg + '\n\n'
    msg = msg +'Adding the eicar test signature for positive virus detection'
    msg = msg + '\n\n'
    msg = msg + 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    subject = subject + ' VIRUS:True'

if options.verbose:
    print('usetls:', options.usetls)
    print('usessl:', options.usessl)
    print('from address:', fromaddr)
    print('to address:', toaddr)
    print('server address:', serveraddr)
    print('server port:', options.serverport)
    print('smtp username:', options.SMTP_USER)
    print('smtp password: *****')
    print('smtplib debuglevel:', options.debuglevel)
    print('spam: ', options.spam)
    print('virus: ', options.virus)
    print("-- Message body ---------------------")
    print(msg)
    print("-------------------------------------")

send_mail(fromaddr, toaddr, subject, msg, file=options.attach,
          server=serveraddr,port=options.serverport, ssl=options.usessl, tls=options.usetls,debuglevel=options.debuglevel)
