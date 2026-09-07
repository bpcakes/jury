# Lifecycle Probes

Unpublished CP-19 test tooling for allocation quarantine and deterministic
protection-setup fault models.

The test allocator delays deallocation so released heap blocks remain valid for
inspection. It is a test process implementation detail, not a runtime allocator
offered by the `sanitization` crate.
