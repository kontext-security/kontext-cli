package hubspotpolicy

import (
	"strings"
)

// Canonical HubSpot action names emitted by the classifier, mirroring the
// shared action catalog (packages/shared/src/hubspot/action-catalog.ts):
//
//	hubspot.object.read / hubspot.object.write — CRM data; the object type is
//	  the resource anchor (Resource), normalized to canonical names.
//	hubspot.api.read / hubspot.api.write — everything else the connector
//	  exposes: account/user info, marketing analytics, landing pages,
//	  connector utilities.
const (
	ActionObjectRead  = "hubspot.object.read"
	ActionObjectWrite = "hubspot.object.write"
	ActionAPIRead     = "hubspot.api.read"
	ActionAPIWrite    = "hubspot.api.write"
)

// ProviderAction is one classified HubSpot action. Resource is the CRM
// object type (e.g. "contacts") when the tool input names one, otherwise
// empty ("any resource" for rule-matching purposes).
type ProviderAction struct {
	Action   string
	Resource string
}

// ConnectorResolver resolves an MCP server segment (the middle part of an
// "mcp__<server>__<tool>" tool name) against Cowork's per-session connector
// registry. resolved=false means the registry could not answer (no config
// file, unknown id) and the tool-name fallback decides; resolved=true with
// isHubspot=false is a definitive counter-signal — the segment maps to a
// different server — and suppresses classification even for HubSpot-looking
// tool names.
type ConnectorResolver func(serverSegment string) (isHubspot, resolved bool)

// toolClassification says how one HubSpot connector tool maps to canonical
// actions. Exactly one of the fields drives the mapping.
type toolClassification struct {
	action string
	// objectTyped tools carry the CRM object type in their input; the
	// classifier extracts and normalizes it into Resource.
	objectTyped bool
	// actionInput tools (manage_landing_page) are read or write depending on
	// their "action" input value.
	actionInput bool
}

// hubspotTools is the full tool surface of the remote HubSpot MCP server,
// verified against live Cowork sessions and the connector's published input
// schemas (ENG-466). Unknown tools from the connector fall back to
// hubspot.api.read/write by name heuristics in classifyTool.
var hubspotTools = map[string]toolClassification{
	// CRM data reads — objectType is a mandatory input on the search/get
	// tools and present on the property tools.
	"search_crm_objects": {action: ActionObjectRead, objectTyped: true},
	"get_crm_objects":    {action: ActionObjectRead, objectTyped: true},
	"search_properties":  {action: ActionObjectRead, objectTyped: true},
	"get_properties":     {action: ActionObjectRead, objectTyped: true},
	// SQL over the whole CRM: a read, but across every object type, so no
	// single resource anchor. Matches wildcard-resource rules only.
	"query_crm_data": {action: ActionObjectRead},
	// The connector's only CRM write tool (create/update; it has no delete).
	"manage_crm_objects": {action: ActionObjectWrite, objectTyped: true},
	// Account/marketing reads.
	"get_user_details":              {action: ActionAPIRead},
	"get_organization_details":      {action: ActionAPIRead},
	"search_owners":                 {action: ActionAPIRead},
	"get_campaign_analytics":        {action: ActionAPIRead},
	"get_campaign_asset_metrics":    {action: ActionAPIRead},
	"get_campaign_contacts_by_type": {action: ActionAPIRead},
	"get_content_analytics_report":  {action: ActionAPIRead},
	"render_landing_page_ui":        {action: ActionAPIRead},
	"tool_guidance":                 {action: ActionAPIRead},
	"submit_feedback":               {action: ActionAPIRead},
	// Landing pages: one tool for both directions; the "action" input value
	// decides read vs write.
	"manage_landing_page": {action: ActionAPIWrite, actionInput: true},
}

// landingPageReadActions are the side-effect-free values of
// manage_landing_page's "action" input, per the connector's input schema.
// Unknown values classify as write (fail conservative).
var landingPageReadActions = map[string]bool{
	"MODULES":       true,
	"MODULE_TYPES":  true,
	"MODULE_DEF":    true,
	"MODULE_STYLES": true,
	"MODULE_GUIDE":  true,
	"TEMPLATES":     true,
	"REVIEW":        true,
}

// standardObjectTypeIDs maps HubSpot's numeric object-type ids to their
// canonical names, so a rule pinned on "contacts" matches regardless of which
// spelling the tool input carried. Unmapped ids (custom objects "2-…" and
// rarer standard objects) pass through verbatim — a rule can pin the raw id
// and the audit trail shows exactly what was touched.
var standardObjectTypeIDs = map[string]string{
	"0-1": "contacts",
	"0-2": "companies",
	"0-3": "deals",
	"0-5": "tickets",
	"0-7": "products",
	"0-8": "line_items",
}

// ClassifyProviderActions classifies one hook event's tool call into
// canonical HubSpot actions. Only MCP tool calls are classified: the HubSpot
// surface reachable from Claude Cowork / Claude Code is the remote MCP
// connector, so there is no shell or URL grammar here (raw api.hubapi.com
// classification is a deliberate non-goal for v1).
//
// The connector is identified in two steps: resolver (Cowork's connector
// registry, matching the server URL host) first, then a tool-name fallback —
// HubSpot's tool names are distinctive enough that a name match alone is
// safe, and the registry file is an undocumented Claude-internal format we
// must not hard-depend on.
func ClassifyProviderActions(toolName string, toolInput map[string]any, resolver ConnectorResolver) []ProviderAction {
	serverSegment, tool, ok := splitMCPToolName(toolName)
	if !ok {
		return nil
	}
	classification, known := hubspotTools[tool]
	if !known {
		return nil
	}
	if !isHubspotServer(serverSegment, resolver) {
		return nil
	}

	switch {
	case classification.actionInput:
		action := ActionAPIWrite
		if value, _ := toolInput["action"].(string); landingPageReadActions[strings.ToUpper(strings.TrimSpace(value))] {
			action = ActionAPIRead
		}
		return []ProviderAction{{Action: action}}
	case classification.objectTyped:
		types := objectTypesFromInput(tool, toolInput)
		if len(types) == 0 {
			return []ProviderAction{{Action: classification.action}}
		}
		actions := make([]ProviderAction, 0, len(types))
		for _, objectType := range types {
			actions = append(actions, ProviderAction{Action: classification.action, Resource: objectType})
		}
		return actions
	default:
		return []ProviderAction{{Action: classification.action}}
	}
}

// splitMCPToolName splits "mcp__<server>__<tool>" into its server segment and
// tool name. The server segment may itself contain "__"-free UUIDs (Cowork
// connectors) or plain names (Claude Code .mcp.json entries).
func splitMCPToolName(toolName string) (server, tool string, ok bool) {
	const prefix = "mcp__"
	if !strings.HasPrefix(toolName, prefix) {
		return "", "", false
	}
	rest := toolName[len(prefix):]
	// The tool name is everything after the LAST "__" so server segments
	// containing "__" (none observed, but cheap to be safe) still split.
	index := strings.LastIndex(rest, "__")
	if index <= 0 || index+2 >= len(rest) {
		return "", "", false
	}
	return rest[:index], rest[index+2:], true
}

// isHubspotServer decides whether the server segment is the HubSpot
// connector. The registry (when it can answer) is authoritative in both
// directions. Without an answer, a segment naming HubSpot directly
// ("hubspot" from .mcp.json, "claude_ai_HubSpot" from a claude.ai connector)
// matches, and an opaque connector-instance id (Cowork UUIDs) carries no
// counter-signal, so the distinctive tool name decides. A named non-HubSpot
// segment ("workspace", "linear") stays unclassified.
func isHubspotServer(segment string, resolver ConnectorResolver) bool {
	if resolver != nil {
		if isHubspot, resolved := resolver(segment); resolved {
			return isHubspot
		}
	}
	return strings.Contains(strings.ToLower(segment), "hubspot") || looksLikeOpaqueID(segment)
}

// looksLikeOpaqueID reports whether the server segment is an opaque
// connector-instance id (Cowork UUIDs) rather than a human-chosen name. Only
// consulted when no registry is available: an opaque id carries no counter-
// signal, so the distinctive tool name decides.
func looksLikeOpaqueID(segment string) bool {
	if len(segment) < 16 {
		return false
	}
	for _, r := range segment {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r == '-':
		default:
			return false
		}
	}
	return true
}

// objectTypesFromInput extracts the CRM object type(s) a tool call touches.
// Search/get/property tools carry a single top-level objectType;
// manage_crm_objects nests them per object under createRequest/updateRequest,
// and one call may touch several types — each becomes its own action.
func objectTypesFromInput(tool string, input map[string]any) []string {
	if tool != "manage_crm_objects" {
		if objectType := normalizeObjectType(stringField(input, "objectType")); objectType != "" {
			return []string{objectType}
		}
		return nil
	}
	seen := map[string]bool{}
	var types []string
	for _, requestKey := range []string{"createRequest", "updateRequest"} {
		request, _ := input[requestKey].(map[string]any)
		if request == nil {
			continue
		}
		objects, _ := request["objects"].([]any)
		for _, entry := range objects {
			object, _ := entry.(map[string]any)
			if object == nil {
				continue
			}
			objectType := normalizeObjectType(stringField(object, "objectType"))
			if objectType != "" && !seen[objectType] {
				seen[objectType] = true
				types = append(types, objectType)
			}
		}
		// Some request shapes carry the object type at the request level.
		if objectType := normalizeObjectType(stringField(request, "objectType")); objectType != "" && !seen[objectType] {
			seen[objectType] = true
			types = append(types, objectType)
		}
	}
	return types
}

// normalizeObjectType maps HubSpot's numeric object-type ids to canonical
// names and lower-cases name spellings, so policy rules match one canonical
// form. Unmapped ids pass through verbatim.
func normalizeObjectType(objectType string) string {
	objectType = strings.ToLower(strings.TrimSpace(objectType))
	if canonical, ok := standardObjectTypeIDs[objectType]; ok {
		return canonical
	}
	return objectType
}

func stringField(input map[string]any, key string) string {
	value, _ := input[key].(string)
	return value
}
