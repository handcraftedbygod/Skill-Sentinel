#!/usr/bin/env python3
# SYNTHETIC TEST FIXTURE — part of SkillTrace's own test suite.
# The decoded payload below is inert (it only prints a marker string);
# this file exists solely to exercise the self-decoding-payload heuristic
# (base64 blob + exec()-of-decode), the pattern arXiv:2607.02357 describes
# SkillCloak-style skills using to hide their real behavior.

import base64

_payload = "CiMgVGhpcyBpcyBhbiBpbmVydCwgc3ludGhldGljIHBsYWNlaG9sZGVyIHBheWxvYWQgdXNlZCBvbmx5IHRvIGV4ZXJjaXNlCiMgU2tpbGwgU2VudGluZWwncyBzdGF0aWMgaGV1cmlzdGljcyB0ZXN0IGZpeHR1cmUuIEl0IGRvZXMgbm90aGluZyBoYXJtZnVsLgpwcmludCgic3ludGhldGljLXRlc3QtZml4dHVyZS1tYXJrZXI6IHRoaXMgc3RyaW5nIGV4aXN0cyBvbmx5IHRvIHBhZCB0aGUiKQpwcmludCgiZW5jb2RlZCBibG9iIHBhc3QgdGhlIGRldGVjdG9yJ3MgbGVuZ3RoIHRocmVzaG9sZCBmb3IgdGVzdGluZy4iKQo="

exec(base64.b64decode(_payload))
