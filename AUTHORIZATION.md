# Authorization & Responsible Use

Breakero is a security testing tool. It sends real HTTP requests to a target
and tries to reach things a normal user should not be able to reach. **You may
only run it against systems you own or have explicit, written permission to
test.**

Testing a system without authorization is illegal in most countries (for
example, unauthorized access laws such as the US CFAA, the UK Computer Misuse
Act, and Indonesia's UU ITE). Getting a bug does not make the access legal —
permission does.

## Before you scan, make sure you have

- [ ] **Written authorization** naming the exact targets (domains, IPs, apps).
- [ ] **A defined scope** — which hosts are in, which are out.
- [ ] **A testing window** agreed with the system owner.
- [ ] **A point of contact** to notify if something breaks.
- [ ] Confirmation you are testing **non-production** data where possible.

Good places to practise legally, with no permission needed beyond their own
terms:

- **OWASP Juice Shop** (run it locally): <https://owasp.org/www-project-juice-shop/>
- **PortSwigger Web Security Academy**: <https://portswigger.net/web-security>
- **DVWA (Damn Vulnerable Web Application)**: <https://github.com/digininja/DVWA>
- Public bug-bounty programs — **read each program's scope and rules first.**

## How Breakero keeps you inside the lines

These are enforced by the tool, not just suggestions:

1. **Authorization gate.** Breakero refuses to start unless you pass
   `-i-am-authorized` (or set `"authorized": true` in the config). This is your
   attestation that you have permission.
2. **Scope lock.** Every request is checked against your in-scope host list.
   A request to any other host — even via a redirect — is refused and never
   sent. If no scope is set, nothing runs.
3. **Rate limiting.** Requests are paced (default 5/second). Breakero is an
   access-control tester, **not** a stress or denial-of-service tool, and it is
   built so it cannot be used as one by accident.
4. **Request budget.** A global cap (default 2000) stops a run from ballooning.
5. **Read-only by default.** Data-changing methods (POST/PUT/PATCH/DELETE) are
   disabled unless you explicitly pass `-active`. Even then, use them only when
   your authorization covers modifying data.

## Handling findings responsibly

- Treat scan output and any data you see as **confidential**.
- Report issues to the system owner through the agreed channel; do not disclose
  publicly without coordination.
- Do not pivot, escalate, or access more data than needed to demonstrate an
  issue. Confirm, document, stop.

If you are not sure whether you are allowed to test something: **you are not.**
Ask first.
