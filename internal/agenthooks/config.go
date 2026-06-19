package agenthooks

import (
	"errors"
	"maps"
)

const defaultHooksKey = "hooks"

// Config wraps a generic agent hook settings map. The expected JSON shape is:
//
//	{
//	  "hooks": {
//	    "<EventName>": [
//	      {"matcher": "...", "hooks": [{"command": "..."}]}
//	    ]
//	  }
//	}
type Config struct {
	Settings         map[string]any
	HooksKey         string
	HooksDescription string
}

// HooksMap returns the hooks object from the config. A missing hooks key is an
// empty map; a non-object hooks value is left untouched and reported as an
// error because the file belongs to the user.
func (c Config) HooksMap() (map[string]any, error) {
	if c.Settings == nil {
		return nil, errors.New("settings must be a JSON object")
	}
	key := c.hooksKey()
	switch value := c.Settings[key].(type) {
	case nil:
		return map[string]any{}, nil
	case map[string]any:
		return value, nil
	default:
		return nil, errors.New(c.hooksDescription() + " must be a JSON object")
	}
}

// Merge removes existing owned handlers for each event in plan, then inserts
// that event's canonical group. Foreign content is preserved verbatim.
func (c Config) Merge(plan Plan, isOwned CommandPredicate) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	hooks, err := c.HooksMap()
	if err != nil {
		return err
	}

	nextHooks := maps.Clone(hooks)
	for _, event := range plan.sortedEvents() {
		name := event.String()
		groups := c.withoutOwnedHandlers(nextHooks[name], isOwned)
		group, err := plan.Events[event].nativeGroup()
		if err != nil {
			return err
		}
		switch plan.Events[event].normalizedPlacement() {
		case PlacementAppend:
			nextHooks[name] = append(groups, group)
		default:
			return errUnsupportedPlacement(plan.Events[event].Placement)
		}
	}
	c.Settings[c.hooksKey()] = nextHooks
	return nil
}

// Remove strips owned handlers from the selected events and prunes event keys
// or the top-level hooks key when they become empty. Foreign hooks survive.
func (c Config) Remove(plan Plan, isOwned CommandPredicate) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	hooks, err := c.HooksMap()
	if err != nil {
		return err
	}

	nextHooks := maps.Clone(hooks)
	for _, event := range plan.sortedEvents() {
		name := event.String()
		if _, present := nextHooks[name]; !present {
			continue
		}
		groups := c.withoutOwnedHandlers(nextHooks[name], isOwned)
		if len(groups) == 0 {
			delete(nextHooks, name)
			continue
		}
		nextHooks[name] = groups
	}
	if len(nextHooks) == 0 {
		delete(c.Settings, c.hooksKey())
	} else {
		c.Settings[c.hooksKey()] = nextHooks
	}
	return nil
}

// HasCommand reports whether any command handler in any event matches the
// predicate. Unparseable entries are ignored.
func HasCommand(hooks map[string]any, match CommandPredicate) bool {
	if match == nil {
		return false
	}
	for _, raw := range hooks {
		list, ok := raw.([]any)
		if !ok {
			continue
		}
		for _, entry := range list {
			group, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			handlers, _ := group["hooks"].([]any)
			for _, handler := range handlers {
				handlerMap, ok := handler.(map[string]any)
				if !ok {
					continue
				}
				if handler, ok := commandHandlerFromMap(handlerMap); ok && match(handler) {
					return true
				}
			}
		}
	}
	return false
}

// WithoutOwnedHandlers filters owned handlers out of every matcher group in an
// event's group list, dropping groups left without handlers. Unparseable
// entries are kept verbatim.
func WithoutOwnedHandlers(raw any, isOwned CommandPredicate) []any {
	return Config{}.withoutOwnedHandlers(raw, isOwned)
}

func (c Config) withoutOwnedHandlers(raw any, isOwned CommandPredicate) []any {
	list, ok := raw.([]any)
	if !ok {
		if raw == nil {
			return nil
		}
		return []any{raw}
	}
	filtered := make([]any, 0, len(list))
	for _, entry := range list {
		group, ok := entry.(map[string]any)
		if !ok {
			filtered = append(filtered, entry)
			continue
		}
		handlers, ok := group["hooks"].([]any)
		if !ok {
			filtered = append(filtered, entry)
			continue
		}
		kept := make([]any, 0, len(handlers))
		for _, handler := range handlers {
			if handlerMap, ok := handler.(map[string]any); ok {
				if handler, ok := commandHandlerFromMap(handlerMap); ok && isOwned != nil && isOwned(handler) {
					continue
				}
			}
			kept = append(kept, handler)
		}
		if len(kept) == 0 {
			continue
		}
		nextGroup := maps.Clone(group)
		nextGroup["hooks"] = kept
		filtered = append(filtered, nextGroup)
	}
	return filtered
}

func (c Config) hooksKey() string {
	if c.HooksKey != "" {
		return c.HooksKey
	}
	return defaultHooksKey
}

func (c Config) hooksDescription() string {
	if c.HooksDescription != "" {
		return c.HooksDescription
	}
	return c.hooksKey()
}
