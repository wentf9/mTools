package guardrail

import (
	"context"
	"fmt"

	"example.com/MikuTools/pkg/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Guardrail coordinates risk classification, policy evaluation, approval,
// and audit logging for MCP tool invocations.
type Guardrail struct {
	policy           *Policy
	audit            *AuditLogger
	noElicitFallback string
}

// New creates a Guardrail from configuration. If cfg is nil, defaults are used.
func New(cfg *config.GuardrailConfig) *Guardrail {
	if cfg == nil {
		cfg = DefaultGuardrailConfig()
	}
	fallback := cfg.NoElicitFallback
	if fallback == "" {
		fallback = FallbackDowngrade
	}
	return &Guardrail{
		policy:           NewPolicy(cfg),
		audit:            NewAuditLogger(cfg.AuditLog),
		noElicitFallback: fallback,
	}
}

// WithGuardrail wraps any typed tool handler with the full guardrail pipeline:
// classify -> policy -> approval -> execute -> audit.
//
// riskInputFn extracts a RiskInput from the tool-specific input type.
func WithGuardrail[In, Out any](
	g *Guardrail,
	toolName string,
	riskInputFn func(In) RiskInput,
	handler mcp.ToolHandlerFor[In, Out],
) mcp.ToolHandlerFor[In, Out] {
	if g == nil {
		return handler
	}

	return func(ctx context.Context, req *mcp.CallToolRequest, input In) (*mcp.CallToolResult, Out, error) {
		ri := riskInputFn(input)
		ri.ToolName = toolName

		risk := Classify(ri)
		decision := g.policy.Evaluate(risk, ri)

		entry := AuditEntry{
			Tool:      toolName,
			NodeID:    ri.NodeID,
			Command:   ri.Command,
			Paths:     ri.Paths,
			RiskLevel: risk.String(),
			Decision:  decision.String(),
		}

		switch decision {
		case Deny:
			entry.Outcome = "denied"
			g.audit.Log(entry)
			var zero Out
			return nil, zero, fmt.Errorf("guardrail: operation denied — blocked by security policy")

		case NeedApproval:
			if err := RequestApproval(ctx, req.Session, risk, ri, g.noElicitFallback); err != nil {
				entry.Outcome = "denied"
				entry.Error = err.Error()
				g.audit.Log(entry)
				var zero Out
				return nil, zero, err
			}
			entry.Decision = "approved"
		}

		result, output, err := handler(ctx, req, input)

		entry.Outcome = "executed"
		if err != nil {
			entry.Outcome = "error"
			entry.Error = err.Error()
		}
		g.audit.Log(entry)

		return result, output, err
	}
}
