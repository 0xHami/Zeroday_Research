# RBC Mobile Banking App - Improper Input Validation in Mobile Remote Deposit Capture

| Field | Value |
| --- | --- |
| Vulnerability name | Improper Input Validation in Mobile Remote Deposit Capture |
| Vulnerability type | software |
| Product name | RBC Mobile Banking App |
| Product vendor | Royal Bank Canada |
| Product version | Unknown |
| Product link | https://play.google.com/store/apps/details?id=com.rbc.mobile.android&hl=en |
| Product environment | web |
| Severity | High |
| CVSS score | 7.1 |
| CVSS vector | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N |
| Affected assets | 1 |
| Affected users | 17000000 |
| Date of reporting | Jan 18, 2025 |
| Vendor acknowledgement | Yes |
| Credit | 0xhamy |
| Date published | 2026-02-17T07:20:50.083834+00:00 |
| Last modified | 2026-02-17T07:25:46.21704+00:00 |

---

# Description

**RBC Mobile Banking Application (Android)** is vulnerable to a **business logic flaw allowing cheque amount manipulation** during the *Deposit a Cheque* workflow.

The mobile remote deposit capture (RDC) feature allows users to scan the front and back of a cheque and manually enter the cheque amount. The backend processes the deposit based on the user-supplied amount without properly validating it against:

* The amount written on the cheque image
* The encoded MICR line data
* Clearing/issuer-side verification before crediting funds

Because the application trusts client-supplied input for a financial value, attackers can submit a higher amount than the actual cheque value. The manipulated amount is processed and credited, resulting in unauthorized financial gain.

This constitutes **improper server-side validation and parameter manipulation** in a financial transaction workflow.

---

## Vulnerability Details

Authenticated users can:

* Use the *Deposit a Cheque* feature
* Scan a valid cheque
* Manually enter an amount higher than the real cheque value
* Submit the transaction successfully

The backend does not properly cross-verify the entered amount with the cheque’s actual value before crediting the account.

In testing:

* A CRA-issued cheque for **$239.76**
* Was successfully deposited as **$240.00**
* The inflated amount was processed

Even small discrepancies demonstrate that:

* The amount field is client-controlled
* The backend does not enforce strict validation
* Financial transaction integrity can be altered

If exploitable at scale, this may allow:

* Repeated small-value inflation
* Larger cheque inflation attempts
* Systemic financial abuse
* Regulatory and compliance risk

---

# Steps to Reproduce

1. **Obtain a valid cheque that has not been deposited.**

2. **Open the RBC Mobile App (Android).**

3. Navigate to:

   ```
   Deposit a Cheque
   ```

4. **Scan the front and back of the cheque** as instructed.

5. **When prompted to enter the cheque amount**, input a value slightly higher than the real amount written on the cheque.

   Example:

   * Actual cheque value: `239.76`
   * Entered value: `240.00`

6. **Submit the deposit.**

7. Observe that:

   * The transaction is accepted
   * The higher amount is credited to the account

Example transaction description:

```
Mobile cheque deposit - 1818 on chequing account XXXXX
```

---

# Impact

* Direct financial integrity violation
* Unauthorized monetary gain
* Potential large-scale fraud vector
* Reputational and regulatory exposure
* Abuse possible by any authenticated user

---

# Recommendation

* **Enforce strict server-side validation** of cheque amounts before crediting funds.
* **Cross-verify entered amount** against:

  * OCR-extracted cheque value
  * MICR-encoded data
  * Clearing-house verification responses
* **Do not rely on client-supplied financial values**.
* Implement backend reconciliation before making funds available.
* Add fraud detection for mismatched cheque/image amount discrepancies.
* Consider delayed credit until issuer-side validation completes.
