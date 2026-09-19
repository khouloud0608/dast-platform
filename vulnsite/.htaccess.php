# Deliberately insecure: set a session cookie WITHOUT HttpOnly/Secure/SameSite
# so the passive scanner flags insecure-cookie findings.
# (No security headers are added anywhere, so CSP/X-Frame-Options/etc. are all
# reported missing by the passive scanner — which is the intended result.)
Header always set Set-Cookie "VULNSHOP_SESSION=abc123def456; path=/"
