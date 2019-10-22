"""
Author: Rajagopalan Ranganathan



SSL Certificate verification - using python3 and openssl libraries
"""




import OpenSSL.SSL
import socket
import sys
from ssl import match_hostname
from datetime import datetime
from binascii import hexlify
from OpenSSL import crypto
import requests
import locale
import urllib
import re


"""
Function: Verify_CRL_WithCert
@:parameter crl_link CRL Link Retrieved from the Certificate
@:parameter cert - The Certificate from where the CRL link was retrieved
@:return Boolean value  "True" -- Certificate is good, "False" -- Certificate is Bad
"""


def Verify_CRL_WithCert(crl_link, cert):
    ret = True
    try:
        # Retrieve the file from the URL and store it locally
        urllib.request.urlretrieve(crl_link.decode(), "crl_file.crl")

    except Exception as exp:
        #print(exp)
        return True
    # We need to open the saved file in binary mode
    with open('crl_file.crl', 'rb') as _crl_file:
        try:
            crl = b"".join(_crl_file.readlines())
        except Exception as exp:
            #print(exp)
            return False

    crl_object = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, crl)
    if crl_object:
        try:
            revoked_objects = crl_object.get_revoked()
            #Hexadecimal encoded values
            cert_serial_num = "%X" % (cert.get_serial_number(),)
            if revoked_objects:
                for revobj in revoked_objects:
                    revoked_serial = revobj.get_serial().decode()
                    if revoked_serial == cert_serial_num:
                        return False

        except Exception as exp:
            ret = False
            print(exp)

    return ret

"""
Function: GetCRL_crlLink
@:parameter cert - Certificate from which we need to check if there is a CRL, if so extract the CRL -
CRL - Certificate Revocation List pointed by a URL
@:return - Link obtained from the Certificate, if not "None"
"""


def GetCRL_crlLink(cert):
    try:
        for i in range(0, cert.get_extension_count()-1):
            # Python3 byte sreams: hence we need to use b. Check for any match for CRL distribution points
            if(cert.get_extension(i).get_short_name().find(b'crlDistributionPoints')!=-1):
                crl_link_start = cert.get_extension(i).get_data().find(b'http')
                if crl_link_start != -1:
                    return (cert.get_extension(i).get_data()[crl_link_start:])
    except OpenSSL.crypto.Error:
        # there is no need to raise an error, as getting a CRL link might not work for all the certificates
        pass

"""
Wrapper Method to call the other basic functions to do the CRL Validation
Function: validate_CRL
@:parameter - Cert - Certificate for which CRL needs to be validated
@:return -- Boolean "True" Certificate is good, "False" Certificate is bad i.e. "revoked"
"""


def validate_CRL(cert):
    # Retreive the CRL link if any from the certificate
    crlLink = GetCRL_crlLink(cert)
    #For a Valid CRL link , check if the current certificate is revoked or not
    if crlLink:
        if Verify_CRL_WithCert(crlLink, cert) is False:
            print("Exiting due to error:")
            print("CRL Link:", crlLink.decode())
            print("Certificate Has been Revoked!!!!")
            return False
    return True

"""
Function: print_basic_data_Cert
@:parameter cert - Certificate whose Details needs to be printed
@:parameter num - The Certificate Number in the Chain
@:return - Nothing Void Function
"""


def print_basic_data_Cert(cert,num):
    print("=" * 25, "Start Certificate ", num, "Data", "=" * 25)
    print("Certificate ", num, ":")
    print("Issuer:")
    print("\t- Organization Name: ", cert.get_issuer().O)
    print("\t- Organization Unit: ",cert.get_issuer().OU)
    print("\t- Common Name: ", cert.get_issuer().CN)
    print("Subject:")
    print("\t- Organization Unit: ", cert.get_subject().O)
    print("\t- Organization Unit: ", cert.get_subject().OU)
    print("\t- Common Name: ", cert.get_subject().CN)
    print("=" * 25, "End Certificate ", num, "Data", "=" * 25)




"""
Function: verify_cb
@:parameters: Call back parameters from SSL context
Connection, certificate, errno, errdepth,retcode

Does the Following Verification
1) Check for certificate Expiry
2) Check for Trust - At least on in the chain
3) Check/Validate CRL
3) Check for Host Name

Uses Static variables/Flags

@:return Boolean True - Validation OK, False  Validation Not OK
"""

"""
A part of this Code is understood and rewritten from:
https://wiki.python.org/moin/SSL
"""

def verify_cb(conn, x509, errno, errdepth, retcode):
    """
      callback for certificate validation
      should return true if verification passes and false otherwise
    """
    # Increment the Static variable cert_counter - Certificate Number
    verify_cb.cert_counter += 1
    # Print the basic Certificate Data as Requested
    print_basic_data_Cert(x509, verify_cb.cert_counter)

    # Verify the Certificate has Expired or not
    if x509.has_expired() is True:
        exp_time = x509.get_notAfter().decode()
        print("Exiting due to error:")
        print("Certificate has Expired. Expiration Date:", exp_time[:4]+"."+exp_time[4]+exp_time[5]+"."+exp_time[6]+exp_time[7])
        return False

    # Validate the CRL of the Certificate
    if validate_CRL(x509) is False:
        return False

    # Verify that We can find the Sub-CA or CA in our Certificate Store
    # Note we need to just verify one certificate and it is enough
    if verify_cb.cert_ca_trust is False:
        cert_store = ctx.get_cert_store()
        cert_store_ctx = crypto.X509StoreContext(cert_store, x509)
        try:
            if cert_store_ctx.verify_certificate() is None:
                verify_cb.cert_ca_trust = True
                print("\nCertificate Has been Verified with Trusted CA Certificate List in the System Store\n")
        except Exception as exp:
            pass


    # Set the errno back to "0" , Since if we had to exit from a hard fault or Exception
    # We would have done so, Some Exceptions are excepted until the Last Certificate in the
    # Chain is Verified
    errno = 0

    if errno == 0:
        if errdepth != 0:
            # don't validate names of root certificates
            return True
        else:
            # We are at the last certificate and certificate trust has not been verified
            if verify_cb.cert_ca_trust is False:
                print("Exiting due to error:")
                print("Certificate Trust Cannot be Verified")
                return False
            sal = ""
            try:
                for i in range(0, x509.get_extension_count() - 1):
                    if (x509.get_extension(i).get_short_name().find(b'subjectAltName') != -1):
                        sal = sal + str(x509.get_extension(i))
            except OpenSSL.crypto.Error:
                pass

            sal_list = sal.split('DNS:')
            sal = ''.join(sal_list)

            domain = "*." + host
            if x509.get_subject().CN == host or x509.get_subject().CN == "*."+host or x509.get_subject().CN == "*."+domain.split('.', 1)[1]:
                return True
            else:
                host_name_variations = ""
                if host.find("www") != -1:
                    host_split = host.split(".")
                    host_name_variations = host_split[1] + "." + host_split[2]
                if sal.find(host) != -1:
                    return True
                if sal.find("*." + host) != -1:
                    return True
                if sal.find("*." + domain.split('.', 1)[1]) != -1:
                    return True
                if host_name_variations:
                    if sal.find(host_name_variations) != -1:
                        return True
                print("Exiting due to error:")
                print("Hostname Doesnt match !!! \nExpected Hostname: ", host, "\nGot: ", x509.get_subject().CN)
                return False

    else:
        return False

# Static Varaibles of the Function
verify_cb.cert_counter = 0
verify_cb.cert_ca_trust = False


"""
Function: main
:Parameter : 2 args
1) Host - host to connect
2) Port  - Remote host Port to connect

Set the SSL context, Does the SSL handshake and then prints the webpage contents if the SSL Certificate Validation is Successful
"""

if __name__ == "__main__":

    if len(sys.argv) != 3:
        print("Invalid Number of Arguments. Usage: python3 ssl3.py <Hostname> <port-number>")
        sys.exit(1)
    try:
        host = sys.argv[1]
    except:
        sys.exit(1)

    ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
    ctx.set_verify(OpenSSL.SSL.VERIFY_PEER | OpenSSL.SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb)
    ctx.load_verify_locations(None, "/etc/ssl/certs/")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.connect((host, 443))
    except socket.error:
        print("can't connect")
        sys.exit(1)

    ssl = OpenSSL.SSL.Connection(ctx,s)
    ssl.setblocking(True)
    ssl.set_connect_state()

    try:
        ssl.set_connect_state()
        ssl.do_handshake()
    except Exception as e:
        print("Exception Raised from SSL Handshake", e)
        exit("[-] ssl handshake error")

    peercertchain = ssl.get_peer_cert_chain()
    for cert in peercertchain:
        print_basic_data_Cert(cert,1)

    print("\nSSL Certificate Validation Done!! Connected to the Host:", host, "\n")
    print("\nThe Web-page Content is as Follows:\n")
    try:
        req = requests.get('https://'+host)
    except Exception as exp:
        print("Exiting Due to Error:", exp)
        exit()
    print("#" * 30, "Start Content", "#" * 30)
    print(req.content)
    print("#" * 30, "End Content", "#" * 30)

    # Close the Request
    req.close()

    # Shutdown
    s.shutdown(0)

    # Debug Code
    # To get and print the entire Peer  Certificate Chain - Dump the Certificate with all the Data
    # Un-comment the below lines only for debugging

    """
    peercert = ssl.get_peer_certificate()
    peercertchain = ssl.get_peer_cert_chain()
    digest = str(peercert.digest('sha1')).replace(":", "").lower()
    print ("\n\npeer cert chain:\n")
    for cert in peercertchain:
        print_Cert_All_Fields(cert)
    """

"""
def print_Cert_All_Fields(cert):
    #print ("SHA1 digest: " + str(cert.digest("sha1")))
    print("SHA1 digest: " + cert.digest("sha1").decode())
    print("MD5  digest: " + cert.digest("md5").decode())
    print( "\ncert details\nissuer: ")
    for (a,b) in cert.get_issuer().get_components():
        print("\t"+a.decode()+": "+b.decode())

    print ("pubkey type: "+str(cert.get_pubkey().type()))
    print ("pubkey bits: "+str(cert.get_pubkey().bits()))
    print ("serial:      "+str(cert.get_serial_number()))
    print ("signalgo:    "+cert.get_signature_algorithm().decode())
    print ("subject:")
  for (a,b) in cert.get_subject().get_components():
    print ("\t"+a.decode('utf-8')+": "+b.decode('utf-8'))

    print ("version:     "+str(cert.get_version()))
    print ("not before:  "+cert.get_notBefore().decode())
    print ("not after:   "+cert.get_notAfter().decode())

    print ("\nextensions:")
    try:
        for i in range(0,cert.get_extension_count()-1):
            print (cert.get_extension(i))
    except OpenSSL.crypto.Error:
        pass
    print ("#"*72)
"""






