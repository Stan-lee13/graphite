package graphite

// IntentTypes is every value `ProposedIntent.IntentType` may carry, in the
// order of schemas/proposed-intent-v1.json: the Core's canonical intents,
// their synonyms, and "unknown". Anything else the Core refuses as an
// unknown intent type (fail closed).
//
// Round 30 added "withdraw", "claim", "burn" and "configure" (with their
// synonyms). They describe only the instructions a grounded grant names
// (graphite-core/src/intent_grants.rs), when the transaction's own accounts
// show the operation is the signer's own; anything else they label is
// refused.
var IntentTypes = []string{
	"swap", "trade", "exchange", "transfer", "send", "stake", "delegate",
	"close", "close_account", "create", "create_account", "approve", "revoke",
	"withdraw", "redeem", "remove_liquidity", "decrease_liquidity",
	"claim", "claim_fees", "claim_rewards", "collect_fees", "harvest",
	"burn", "configure", "update_config", "unknown",
}

// IsKnownIntentType reports whether s is one of IntentTypes. It is a
// convenience for callers building a request; the Core decides, and refuses
// an intent outside its vocabulary whatever this says.
func IsKnownIntentType(s string) bool {
	for _, t := range IntentTypes {
		if t == s {
			return true
		}
	}
	return false
}
