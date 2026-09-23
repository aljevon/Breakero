# Permission and responsible use

Breakero sends real requests at a target and tries to reach things a normal user can't. So run it only against systems you own or have been given clear, written permission to test. That's the whole rule.

Testing something without that permission is illegal in most places. In the US there's the CFAA. The UK has the Computer Misuse Act. Indonesia has UU ITE. And plenty of other countries have their own version. Finding a real bug doesn't make the access legal. Permission does.

## Before you point it at anything

- [ ] You have **written permission** that names the exact targets (domains, IPs, apps).
- [ ] The **scope** is agreed. You know what's in and what's off-limits.
- [ ] There's a **testing window** the owner signed off on.
- [ ] You've got a **contact** to call if something breaks.
- [ ] Where possible, you're hitting **non-production** data.

Want to practice without any of that? These are made to be attacked, and their own terms cover it:

- **OWASP Juice Shop**, run locally: <https://owasp.org/www-project-juice-shop/>
- **PortSwigger Web Security Academy**: <https://portswigger.net/web-security>
- **DVWA**: <https://github.com/digininja/DVWA>
- Public bug-bounty programs. Read the scope and rules for each one first.

## What the tool does to keep you honest

These aren't suggestions in a doc. The code does them.

1. **Authorization gate.** It won't start unless you pass `-i-am-authorized` (or set `"authorized": true`). That flag is you going on record that you have permission.
2. **Scope lock.** Every request gets checked against your list of allowed hosts. Anything else gets dropped before it leaves, even if a redirect tries to pull it somewhere new. No scope, nothing runs.
3. **Speed limit.** Requests are paced, 5 a second by default. This is a testing tool, not a way to hammer a server, and it's built so you can't quietly turn it into one.
4. **Request cap.** A global ceiling (2000 by default) so one run can't balloon.
5. **Read-only by default.** POST, PUT, PATCH and DELETE stay off unless you add `-active`. And even then, only use them if your permission actually covers changing data.

## Once you've found something

- Keep the output and anything you saw to yourself. It's confidential.
- Report it to the owner through whatever channel you agreed on. Don't post it publicly without sorting that out with them first.
- Don't dig deeper than you need to. Confirm the issue, write down enough to prove it, and stop. No pivoting, no grabbing extra data.

Not sure you're allowed to test something? Then you're not. Ask first.
