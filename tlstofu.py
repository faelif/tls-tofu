#!/usr/bin/env python3
#
#

import pathlib  # to find config directory
import os  # to make config directory
import datetime  # for datetime.now()
import ssl  # for ssl.CertificateError
import ipaddress  # to test if an address is an ipaddress
import re  # to match hostnames to eachother

import sqlite3

from cryptography import x509  # to check dates and match hostname

# Folder for TLS-TOFU config
CONF_DIR = pathlib.Path("~/.config/tls-tofu").expanduser()
# TOFU known_hosts database. This is stored per-user.
USER_TLS_TOFU_DB = CONF_DIR / "known_hosts.db"

os.makedirs(CONF_DIR, exist_ok=True)


class CertManager(object):
    def __init__(self, db_path: str = USER_TLS_TOFU_DB.absolute()):
        self.db_path = db_path
        with sqlite3.connect(self.db_path) as con:
            cur = con.cursor()
            cur.execute(
                "CREATE TABLE IF NOT EXISTS keys (host TEXT, cert BLOB)"
            )

    def add_cert(self, cert: bytes, address: str):
        with sqlite3.connect(self.db_path) as con:
            cur = con.cursor()
            cur.execute(
                "INSERT INTO keys VALUES (?, ?)", (address, cert)
            )

    def get_certs(self):
        with sqlite3.connect(self.db_path) as con:
            cur = con.cursor()
            cur.execute(
                "SELECT * FROM keys"
            )
            return cur.fetchall()

    def verify_cert(self, cert: bytes, address: str):
        for i in self.get_certs():
            if i[0] == address:
                if i[1] == cert:
                    return True
                else:
                    raise CertMismatchError(
                        "The specified address has a certificate that does "
                        "not match that in the pre-existing database"
                    )
        raise CertNotFoundError(
            "The specified address was not located in the pre-existing "
            "database"
        )


cert_manager = CertManager()


class CertInvalidError(ssl.CertificateError):
    pass


class CertUntrustedError(ssl.CertificateError):
    pass


class CertDatetimeError(CertInvalidError):
    pass


class CertAddressError(CertInvalidError):
    pass


class CertMatchingError(CertUntrustedError):
    pass


class CertNotFoundError(CertUntrustedError):
    pass


class CertMismatchError(CertUntrustedError):
    pass


def validate_cert(cert: bytes, hostname: str = None):
    """
    Takes DER-encoded cert as returned from ssock.getpeercert(binary_form=True)
    and validates it, checking if it matches a given address (optional) and
    making sure that it's within the bounds in the `Validity' section of the
    cert.

    Inputs:
        cert: bytes
            The DER-encoded certificate to validate.

        hostname: str = None
            A hostname to match against. If it is falsey, no hostname checking
            is performed. If it is truthy, it is checked for equality against
            the subjectAltNames and commonName of the cert.

    Outputs:
        If the cert is valid for the hostname and current time, outputs `True'.
        Otherwise, raises an exception giving more detail.

    Raises:
        CertDatetimeError (subclass of CertInvalidError)
            This is raised if the supplied certificate is either past expiry
            or is not yet valid

        CertAddressError (subclass of CertInvalidError)
            This is raised if the supplied certificate has an invalid address
            in it's altNames or commonName

        CertMatchingError (subclass of CertUntrustedError)
            This is raised if the address supplied does not appear in the
            certificate's altNames or commonName
    """
    return_value = False

    parsed_cert = x509.load_der_x509_certificate(cert)
    now = datetime.datetime.utcnow()
    if parsed_cert.not_valid_before > now:
        raise CertDatetimeError(
            f"The supplied certificate is not valid until"
            f"{parsed_cert.not_valid_before}"
        )
    elif parsed_cert.not_valid_after < now:
        raise CertDatetimeError(
            f"The supplied certificate is not valid after"
            f"{parsed_cert.not_valid_after}"
        )

    if hostname:
        names = []
        ips = []
        cert_common_name = parsed_cert.subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME
        )[0].value
        names.append(cert_common_name)
        try:
            alt_names = parsed_cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ).value
        except x509.ExtensionNotFound:
            pass
        else:
            alt_hostnames = alt_names.get_values_for_type(
                x509.DNSName
            )
            alt_ips = alt_names.get_values_for_type(
                x509.IPAddress
            )
            names.extend(alt_hostnames)
            ips.extend(alt_ips)

        try:  # If the hostname is an IP address...
            host_ip = ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            for i in ips:  # ... does it match one in the subjectAltNames?
                if ipaddress.ip_address(i) == host_ip:
                    return_value = True

        for i in names:
            # Is the cert's name or hostname an IDN?
            if i[:4] == "xn--" or hostname[:4] == "xn--":
                # If so, don't expand wildcards and match case-insensitively
                if hostname.lower() == i.lower():
                    return_value = True
            else:
                # get sections of a dNSName, as a left-most component and a
                # domain
                dns_name_components = i.split(".", 1)
                left_component = dns_name_components[0]
                if "*" in left_component:  # Is it a wildcard cert?
                    host_name_components = hostname.split(".", 1)

                    # Do the domain parts match?
                    if host_name_components[1] == dns_name_components[1]:
                        # If so, check the left-most component with wildcards
                        if left_component.count("*") > 1:
                            # If the dNSName has more than one asterisk, it's
                            # invalid
                            raise CertAddressError(
                                "The supplied certificate contains an invalid "
                                "dNSName containing two or more asterisks."
                            )
                        else:
                            # Use regex to detect matches
                            regex = left_component.replace(
                                "*",
                                "[A-Za-z0-9-]*"
                            ) + dns_name_components[1]
                            if re.match(regex, hostname):
                                return_value = True

                elif i == hostname:
                    return_value = True

        # If we got this far, no errors have been raised
        if return_value:
            return True
        else:
            # The cert isn't valid for the hostname
            raise CertMatchingError(
                "The supplied certificate is invalid for the supplied address"
            )

    return True
