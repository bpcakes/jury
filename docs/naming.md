# Naming

Jury is the product and CLI name. The category descriptor is:

> Jury is a portable secrets vault with direct and quorum-controlled witnessed
> access paths.

The short positioning line is:

> Portable secrets with configurable distributed authority.

Never apply the quorum-controlled or distributed-authority claim to a direct
recipient slot. A direct recipient is intentionally able to open its authorized
item without a witness; only witnessed slots require the configured parties.
An item containing both slot families is mixed-mode and must not be described
as quorum-controlled as a whole.

The courtroom metaphor stops at the product name. Product and protocol language
must remain technically direct:

| Concept | Preferred term |
| --- | --- |
| Portable encrypted artifact | vault |
| Protected value | secret or item |
| Human or machine identity | principal |
| Authorization service | witness |
| Permission | grant |
| Authorization evidence | receipt |

Do not rename witnesses to jurors, requests to cases, or authorization outcomes
to verdicts in code or protocol schemas. Those metaphors obscure the security
model and make machine authorization sound human-only.

The executable is `jury`. The standalone witness daemon is `juryd`.
