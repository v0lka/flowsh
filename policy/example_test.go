package policy_test

import (
	"fmt"

	"github.com/v0lka/flowsh/api"
	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/policy"
)

func ExamplePolicy_Evaluate() {
	p, err := policy.New(policy.Config{
		Unknown: policy.Deny,
		Cradle:  policy.Deny,
		Effects: map[engine.EffectKind]policy.Action{
			engine.KindCredAccess: policy.Deny,
			engine.KindPrivEsc:    policy.Deny,
			engine.KindNetEgress:  policy.Review,
		},
	})
	if err != nil {
		fmt.Println("invalid policy")
		return
	}
	r, err := api.Analyze(api.LangBash, `echo ready > /tmp/flowsh-policy-example`)
	if err != nil {
		fmt.Println("analysis failed")
		return
	}
	d := p.Evaluate(r)
	fmt.Println(d.Action, d.Allowed())
	// Output: allow true
}
