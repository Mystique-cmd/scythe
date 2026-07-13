# TODO - Scythe atomicity traversal (HIGH-only)

- [ ] Add HIGH-only traversal pass for atomicity checks anchored to the workflow’s “output/produce” (last mutating request)
- [ ] Implement output-anchored atomicity decision + violation reasons
- [ ] Store results on each flow: `flow.atomicity = { isAtomic, anchoredOutput, violations[] }`
- [ ] Update `renderAtomicityDashboard()` to compute metrics using `flow.atomicity.isAtomic` and prioritize HIGH violations
- [ ] Validate Test Bench scenarios (check-act + concurrent-checkact)

