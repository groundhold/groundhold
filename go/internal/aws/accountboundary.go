// D468 — the account boundary on AWS.
//
// D466 and D467 enforced the same property on the other two clouds, where a convention
// already existed and a handful of paths sat outside it (39/44 on GCP, 64/67 on Azure).
// AWS is the opposite case: TWENTY paths bind an account out of the providerId and NONE
// of them checks it. There was no convention to enforce, so this establishes one.
//
// The argument is already written down in this package — in gateIntrusive, which refuses
// an intrusive probe whose resource account differs from the acting identity's, because
// "a forged/stale binding must not redirect a billed restore off-account". That reasoning
// does not stop at probes. A delete carrying a foreign account in its providerId aims at
// another account's resource, and unlike Azure (where every ARM URL is built from the
// driver's own subscription regardless) an AWS ARN names the account directly, so the
// request goes where the binding says. Cross-account access to SQS, SNS, S3 and ECR is
// ordinary and commonly granted, which makes the aim real rather than theoretical.
//
// No legitimate flow produces a foreign-account providerId: the driver holds one
// credential set, `discover` enumerates the acting account, and every create writes the
// account it resolved. A mismatch is a forged or hand-edited binding — the D439 threat
// model — or a stale one from another estate.
//
// The check is a no-op when the account is not resolved. Observe and discover can run
// before any STS call, and D29 forbids turning "we could not find out" into a refusal;
// a run that pinned an identity (apply/converge, where the D75 preflight was checked
// against it) is the one that gains the guard.
package aws

import "fmt"

func (d *Driver) sameAccount(account string) error {
	if d.Account == "" || account == "" {
		return nil
	}
	if account != d.Account {
		return fmt.Errorf("providerId account %q is not the acting account %q — refusing "+
			"to act on a resource in another account", account, d.Account)
	}
	return nil
}
