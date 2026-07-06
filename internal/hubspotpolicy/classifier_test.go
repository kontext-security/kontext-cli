package hubspotpolicy

import (
	"reflect"
	"testing"
)

// coworkUUIDTool builds a tool name the way Claude Cowork emits connector
// tools: the server segment is the connector-instance uuid, observed live as
// e.g. "mcp__5c56899e-3e6c-4803-85ca-ff1912393966__search_crm_objects".
func coworkUUIDTool(tool string) string {
	return "mcp__5c56899e-3e6c-4803-85ca-ff1912393966__" + tool
}

func resolveAlwaysHubspot(string) (bool, bool) { return true, true }
func resolveNeverHubspot(string) (bool, bool)  { return false, true }
func resolveNothing(string) (bool, bool)       { return false, false }

func TestClassifyProviderActions(t *testing.T) {
	tests := []struct {
		name     string
		toolName string
		input    map[string]any
		resolver ConnectorResolver
		want     []ProviderAction
	}{
		{
			name:     "search with objectType is an object read on that type",
			toolName: coworkUUIDTool("search_crm_objects"),
			input:    map[string]any{"objectType": "contacts", "query": "test"},
			resolver: resolveAlwaysHubspot,
			want:     []ProviderAction{{Action: ActionObjectRead, Resource: "contacts"}},
		},
		{
			name:     "numeric object-type id normalizes to the canonical name",
			toolName: coworkUUIDTool("get_crm_objects"),
			input:    map[string]any{"objectType": "0-3"},
			resolver: resolveAlwaysHubspot,
			want:     []ProviderAction{{Action: ActionObjectRead, Resource: "deals"}},
		},
		{
			name:     "unmapped object-type id passes through verbatim",
			toolName: coworkUUIDTool("search_crm_objects"),
			input:    map[string]any{"objectType": "2-12345"},
			resolver: resolveAlwaysHubspot,
			want:     []ProviderAction{{Action: ActionObjectRead, Resource: "2-12345"}},
		},
		{
			name:     "manage_crm_objects emits one write per distinct object type",
			toolName: coworkUUIDTool("manage_crm_objects"),
			input: map[string]any{
				"createRequest": map[string]any{
					"objects": []any{
						map[string]any{"objectType": "contacts"},
						map[string]any{"objectType": "0-1"}, // same type, other spelling
					},
				},
				"updateRequest": map[string]any{
					"objects": []any{
						map[string]any{"objectType": "Deals"},
					},
				},
			},
			resolver: resolveAlwaysHubspot,
			want: []ProviderAction{
				{Action: ActionObjectWrite, Resource: "contacts"},
				{Action: ActionObjectWrite, Resource: "deals"},
			},
		},
		{
			name:     "manage_crm_objects without a parsable type is still a write",
			toolName: coworkUUIDTool("manage_crm_objects"),
			input:    map[string]any{"confirmationStatus": "confirmed"},
			resolver: resolveAlwaysHubspot,
			want:     []ProviderAction{{Action: ActionObjectWrite}},
		},
		{
			name:     "query_crm_data is a read with no resource anchor",
			toolName: coworkUUIDTool("query_crm_data"),
			input:    map[string]any{"sql": "SELECT lifecyclestage, COUNT(*) FROM contacts GROUP BY 1"},
			resolver: resolveAlwaysHubspot,
			want:     []ProviderAction{{Action: ActionObjectRead}},
		},
		{
			name:     "account-level tools are api reads",
			toolName: coworkUUIDTool("get_user_details"),
			input:    map[string]any{},
			resolver: resolveAlwaysHubspot,
			want:     []ProviderAction{{Action: ActionAPIRead}},
		},
		{
			name:     "submit_feedback is an api write (egress side effect)",
			toolName: coworkUUIDTool("submit_feedback"),
			input:    map[string]any{"feedback": "great"},
			resolver: resolveAlwaysHubspot,
			want:     []ProviderAction{{Action: ActionAPIWrite}},
		},
		{
			name:     "landing page read action classifies as api read",
			toolName: coworkUUIDTool("manage_landing_page"),
			input:    map[string]any{"action": "TEMPLATES"},
			resolver: resolveAlwaysHubspot,
			want:     []ProviderAction{{Action: ActionAPIRead}},
		},
		{
			name:     "landing page write action classifies as api write",
			toolName: coworkUUIDTool("manage_landing_page"),
			input:    map[string]any{"action": "CREATE_FROM_TEMPLATE", "pageName": "Kontext Test Page"},
			resolver: resolveAlwaysHubspot,
			want:     []ProviderAction{{Action: ActionAPIWrite}},
		},
		{
			name:     "unknown landing page action fails conservative to write",
			toolName: coworkUUIDTool("manage_landing_page"),
			input:    map[string]any{"action": "SOME_FUTURE_ACTION"},
			resolver: resolveAlwaysHubspot,
			want:     []ProviderAction{{Action: ActionAPIWrite}},
		},
		{
			name:     "registry counter-signal suppresses a hubspot-named tool",
			toolName: coworkUUIDTool("search_crm_objects"),
			input:    map[string]any{"objectType": "contacts"},
			resolver: resolveNeverHubspot,
			want:     nil,
		},
		{
			name:     "unresolved registry falls back to the distinctive tool name on an opaque id",
			toolName: coworkUUIDTool("search_crm_objects"),
			input:    map[string]any{"objectType": "contacts"},
			resolver: resolveNothing,
			want:     []ProviderAction{{Action: ActionObjectRead, Resource: "contacts"}},
		},
		{
			name:     "claude code style hubspot server segment matches by name",
			toolName: "mcp__claude_ai_HubSpot__search_crm_objects",
			input:    map[string]any{"objectType": "companies"},
			resolver: resolveNothing,
			want:     []ProviderAction{{Action: ActionObjectRead, Resource: "companies"}},
		},
		{
			name:     "named non-hubspot server stays unclassified without registry proof",
			toolName: "mcp__workspace__search_crm_objects",
			input:    map[string]any{"objectType": "contacts"},
			resolver: resolveNothing,
			want:     nil,
		},
		{
			name:     "unknown tool on the hubspot connector stays unclassified",
			toolName: coworkUUIDTool("delete_all_the_things"),
			input:    map[string]any{},
			resolver: resolveAlwaysHubspot,
			want:     nil,
		},
		{
			name:     "non-mcp tools are never hubspot",
			toolName: "Bash",
			input:    map[string]any{"command": "curl https://api.hubapi.com/crm/v3/objects/contacts"},
			resolver: resolveAlwaysHubspot,
			want:     nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := ClassifyProviderActions(test.toolName, test.input, test.resolver)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("ClassifyProviderActions() = %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestSplitMCPToolName(t *testing.T) {
	server, tool, ok := splitMCPToolName("mcp__5c56899e-3e6c__manage_crm_objects")
	if !ok || server != "5c56899e-3e6c" || tool != "manage_crm_objects" {
		t.Fatalf("splitMCPToolName() = %q, %q, %v", server, tool, ok)
	}
	if _, _, ok := splitMCPToolName("Bash"); ok {
		t.Fatal("splitMCPToolName(Bash) should not parse")
	}
	if _, _, ok := splitMCPToolName("mcp__onlyserver"); ok {
		t.Fatal("splitMCPToolName without a tool part should not parse")
	}
}
