package guardrail

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Fallback policies when client does not support Elicitation.
const (
	FallbackDeny      = "deny"      // reject everything that needs approval
	FallbackAllow     = "allow"     // allow all, rely on client-side tool approval
	FallbackDowngrade = "downgrade" // allow moderate ops, still deny dangerous
)

// RequestApproval sends an Elicitation request to the MCP client, asking the
// user to approve a dangerous operation.
//
// If the client does not support Elicitation, it falls back to the configured
// policy (deny / allow / downgrade).
func RequestApproval(ctx context.Context, session *mcp.ServerSession, risk RiskLevel, input RiskInput, fallback string) error {
	if session == nil {
		return fmt.Errorf("guardrail: no session available, cannot request approval")
	}

	msg := buildApprovalMessage(risk, input)

	result, err := session.Elicit(ctx, &mcp.ElicitParams{
		Message: msg,
	})
	if err != nil {
		return applyFallback(err, risk, fallback)
	}

	switch result.Action {
	case "accept":
		return nil
	case "decline":
		return fmt.Errorf("guardrail: operation explicitly declined by user")
	case "cancel":
		return fmt.Errorf("guardrail: operation cancelled by user")
	default:
		return fmt.Errorf("guardrail: unexpected approval response %q, denying", result.Action)
	}
}

// applyFallback decides what to do when Elicitation is not available.
func applyFallback(elicitErr error, risk RiskLevel, fallback string) error {
	switch fallback {
	case FallbackAllow:
		return nil
	case FallbackDowngrade:
		if risk < Dangerous {
			return nil
		}
		return fmt.Errorf("guardrail: dangerous operation denied — client does not support approval and fallback is %q: %w", fallback, elicitErr)
	default: // "deny" or unrecognized
		return fmt.Errorf("guardrail: approval request failed (operation denied): %w", elicitErr)
	}
}

func buildApprovalMessage(risk RiskLevel, input RiskInput) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("⚠️ [Risk: %s] Operation requires your approval\n\n", strings.ToUpper(risk.String())))
	b.WriteString(fmt.Sprintf("Tool:  %s\n", input.ToolName))
	if input.NodeID != "" {
		b.WriteString(fmt.Sprintf("Node:  %s\n", input.NodeID))
	}
	if input.Command != "" {
		b.WriteString(fmt.Sprintf("Command: %s\n", input.Command))
	}
	if input.Sudo {
		b.WriteString("Sudo: yes\n")
	}
	if len(input.Paths) > 0 {
		b.WriteString(fmt.Sprintf("Paths: %s\n", strings.Join(input.Paths, ", ")))
	}
	b.WriteString("\nDo you approve this operation?")
	return b.String()
}
