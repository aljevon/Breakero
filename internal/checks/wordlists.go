package checks

// Community-style wordlists so the access-control checks that normally need a
// config file (roles, object ids, endpoints) still do real work out of the box.
// The point is that a beginner can paste a URL, press Scan, and get meaningful
// IDOR and privilege coverage without ever editing configs/example.json.
//
// Lists are ordered roughly most-common-first, so a small request budget (or a
// low "role guesses" setting) still covers the high-signal cases. They are drawn
// from the patterns pentest communities publish for Broken Access Control work
// (SecLists-style role names, common id parameters, and REST id paths).

// roleNames are identifiers applications use for privileged roles. The
// param-privilege check guesses these as client-controlled role values.
var roleNames = []string{
	"admin", "administrator", "superadmin", "super_admin", "superuser", "super_user",
	"root", "sysadmin", "system", "god", "master", "owner", "operator", "manager",
	"moderator", "mod", "staff", "employee", "supervisor", "editor", "author",
	"developer", "dev", "tester", "qa", "auditor", "analyst", "support", "agent",
	"helpdesk", "billing", "finance", "hr", "sales", "poweruser", "power_user",
	"privileged", "elevated", "webadmin", "siteadmin", "backend", "internal",
	"service", "api", "console", "admins", "administrators", "vip", "premium",
	"gold", "pro", "enterprise", "member", "user", "customer", "client", "guest",
}

// roleParamKeys are query or cookie keys that frequently carry a role or
// privilege flag the server should never trust from the client.
var roleParamKeys = []string{
	"role", "roles", "user_role", "userrole", "is_admin", "isadmin", "isAdmin",
	"admin", "is_staff", "staff", "level", "privilege", "priv", "access",
	"access_level", "group", "usergroup", "user_group", "permission", "permissions",
	"perm", "scope", "type", "user_type", "usertype", "account_type", "membership",
	"tier", "plan", "is_superuser", "superuser", "elevated", "rank", "class",
	"grant", "acl", "mode", "debug", "test", "impersonate", "act_as", "run_as",
}

// roleHeaderKeys are request headers some apps mistakenly trust for the caller's
// role or privilege.
var roleHeaderKeys = []string{
	"X-User-Role", "X-Role", "X-Roles", "X-User-Type", "X-Auth-Role", "X-Privilege",
	"X-Admin", "X-Is-Admin", "X-Access-Level", "X-Group", "X-Permissions",
	"X-User-Level", "X-Auth-Level", "X-Account-Type", "Role",
}

// booleanTruthy are the values used when a vector is a boolean-style flag such
// as admin=<value> or X-Is-Admin: <value>.
var booleanTruthy = []string{"true", "1", "yes", "on"}

// idParamKeys are common names for a query or path parameter that references an
// object by id. The automatic IDOR probe uses them.
var idParamKeys = []string{
	"id", "user_id", "userid", "uid", "account", "account_id", "acct",
	"customer_id", "cid", "order_id", "oid", "doc_id", "document_id", "file",
	"file_id", "fileid", "filename", "object", "object_id", "obj", "ref",
	"reference", "key", "num", "no", "pid", "item", "item_id", "itemid",
	"invoice", "invoice_id", "ticket", "ticket_id", "msg", "message", "message_id",
	"record", "record_id", "row", "profile", "profile_id", "member_id", "mid",
	"node", "post_id", "comment_id", "group_id", "team_id", "project_id",
	"report_id", "transaction_id", "payment_id", "address_id", "card_id",
}

// idPathTemplates are common REST-style paths that embed an object id, written
// with a {id} placeholder. The automatic IDOR probe swaps ids into them.
var idPathTemplates = []string{
	"/api/users/{id}", "/api/user/{id}", "/users/{id}", "/user/{id}",
	"/api/v1/users/{id}", "/api/v2/users/{id}", "/api/accounts/{id}",
	"/account/{id}", "/api/account/{id}", "/api/orders/{id}", "/orders/{id}",
	"/order/{id}", "/api/profile/{id}", "/profile/{id}", "/api/profiles/{id}",
	"/api/documents/{id}", "/documents/{id}", "/document/{id}", "/api/files/{id}",
	"/files/{id}", "/file/{id}", "/api/invoices/{id}", "/invoice/{id}",
	"/invoices/{id}", "/api/tickets/{id}", "/tickets/{id}", "/api/messages/{id}",
	"/messages/{id}", "/api/customers/{id}", "/customers/{id}", "/api/items/{id}",
	"/items/{id}", "/api/records/{id}", "/api/v1/orders/{id}", "/api/cards/{id}",
	"/api/payments/{id}", "/api/reports/{id}", "/api/projects/{id}",
}

// boolishKeys are the role/permission keys that read naturally as a boolean
// "am I privileged" flag rather than a named role.
var boolishKeys = []string{
	"admin", "is_admin", "isAdmin", "is_staff", "staff", "is_superuser",
	"superuser", "elevated", "privileged", "debug",
}

// privVectorsFor builds the ordered list of client-controlled privilege vectors
// the param-privilege check tries, capped at limit. High-signal boolean admin
// flags come first, then role-name guesses across a query parameter, a header
// and a cookie, then wider variety pulled from the role parameter/header
// dictionaries. A larger limit (the app's "role guesses" slider) reaches deeper.
func privVectorsFor(limit int) []privVector {
	if limit <= 0 {
		limit = 14
	}
	seen := map[string]bool{}
	var v []privVector
	add := func(kind, name, val string) bool {
		k := kind + "|" + name + "|" + val
		if seen[k] {
			return len(v) >= limit
		}
		seen[k] = true
		v = append(v, privVector{kind, name, val})
		return len(v) >= limit
	}

	// 1. Highest-signal seed, so even a small "role guesses" setting covers the
	//    classic vectors: admin flags AND ?role=admin across query/header/cookie.
	seed := []privVector{
		{"query", "admin", "true"}, {"query", "role", "admin"},
		{"header", "X-User-Role", "admin"}, {"cookie", "role", "admin"},
		{"query", "is_admin", "1"}, {"query", "isAdmin", "true"},
		{"cookie", "admin", "true"}, {"header", "X-Admin", "true"},
		{"query", "role", "administrator"}, {"header", "X-User-Role", "administrator"},
		{"query", "role", "superadmin"}, {"query", "role", "root"},
		{"cookie", "isAdmin", "1"}, {"query", "role", "manager"},
		{"query", "role", "moderator"}, {"query", "role", "staff"},
		{"header", "X-Is-Admin", "true"}, {"query", "debug", "true"},
	}
	for _, s := range seed {
		if add(s.kind, s.name, s.value) {
			return capVectors(v, limit)
		}
	}
	// 2. Named role guesses: each role name as ?role=, X-User-Role: and cookie role=.
	for _, rn := range roleNames {
		if add("query", "role", rn) || add("header", "X-User-Role", rn) || add("cookie", "role", rn) {
			return capVectors(v, limit)
		}
	}
	// 3. Boolean-style flags across the wider role key dictionary.
	for _, k := range boolishKeys {
		if add("query", k, booleanTruthy[0]) || add("header", "X-"+httpHeaderCase(k), booleanTruthy[0]) || add("cookie", k, booleanTruthy[0]) {
			return capVectors(v, limit)
		}
	}
	// 4. Wider variety: role names across more role parameter and header keys.
	for _, rn := range roleNames {
		for _, pk := range roleParamKeys {
			if add("query", pk, rn) {
				return capVectors(v, limit)
			}
		}
		for _, hk := range roleHeaderKeys {
			if add("header", hk, rn) {
				return capVectors(v, limit)
			}
		}
	}
	return capVectors(v, limit)
}

func capVectors(v []privVector, limit int) []privVector {
	if len(v) > limit {
		return v[:limit]
	}
	return v
}

// httpHeaderCase upper-cases the first letter so a key like "is_admin" becomes a
// plausible header suffix ("Is_admin"); good enough for a spray vector.
func httpHeaderCase(s string) string {
	if s == "" {
		return s
	}
	return string(s[0]-32*btoi(s[0] >= 'a' && s[0] <= 'z')) + s[1:]
}

func btoi(b bool) byte {
	if b {
		return 1
	}
	return 0
}
