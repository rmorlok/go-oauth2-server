package testmode

import (
	"sync"
)

// Action describes one scripted response on a queue. Actions are popped in
// FIFO order. An action with a non-zero Status fully replaces the response
// (skips the real handler); a status-zero action with ScopeOverride set
// passes through to the real handler and rewrites its JSON `scope` field.
type Action struct {
	// Network behavior.
	Status         int               `json:"status,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	Body           string            `json:"body,omitempty"`
	BodyTemplate   string            `json:"body_template,omitempty"`
	DelayMS        int               `json:"delay_ms,omitempty"`
	DropConnection bool              `json:"drop_connection,omitempty"`

	// FailCount applies this action this many times before it is removed
	// from the queue. Zero (or negative) means apply exactly once.
	FailCount int `json:"fail_count,omitempty"`

	// ScopeOverride rewrites the `scope` field of a JSON token response when
	// the action passes through (Status == 0). Pointer-typed so the empty
	// string can encode "omit scope from the response entirely".
	ScopeOverride *string `json:"scope_override,omitempty"`

	// SkipPKCECheck is forward-declared for PR-7. Currently a no-op.
	SkipPKCECheck bool `json:"skip_pkce_check,omitempty"`

	// remaining tracks how many more times this action should fire. Set on
	// enqueue based on FailCount; not exposed in JSON snapshots.
	remaining int
}

// queueKey identifies a per-(client, endpoint) FIFO. clientID == "" is the
// wildcard queue used when no client-specific queue is set.
type queueKey struct {
	clientID string
	endpoint string
}

// ScriptQueue holds per-client/endpoint action queues with FIFO semantics.
type ScriptQueue struct {
	mu     sync.Mutex
	queues map[queueKey][]Action
}

// NewScriptQueue constructs an empty queue.
func NewScriptQueue() *ScriptQueue {
	return &ScriptQueue{queues: make(map[queueKey][]Action)}
}

// Enqueue appends actions to the queue for (clientID, endpoint). Empty
// clientID enqueues onto the wildcard queue.
func (q *ScriptQueue) Enqueue(clientID, endpoint string, actions []Action) {
	q.mu.Lock()
	defer q.mu.Unlock()

	prepared := make([]Action, len(actions))
	for i, a := range actions {
		if a.FailCount > 0 {
			a.remaining = a.FailCount
		} else {
			a.remaining = 1
		}
		prepared[i] = a
	}
	k := queueKey{clientID: clientID, endpoint: endpoint}
	q.queues[k] = append(q.queues[k], prepared...)
}

// Pop returns the next action for a request from clientID at endpoint,
// preferring a client-specific queue over the wildcard queue. The action's
// remaining count is decremented; when it reaches zero the action is
// removed from the queue.
func (q *ScriptQueue) Pop(clientID, endpoint string) (Action, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if a, ok := q.popLocked(queueKey{clientID: clientID, endpoint: endpoint}); ok {
		return a, true
	}
	if clientID != "" {
		if a, ok := q.popLocked(queueKey{clientID: "", endpoint: endpoint}); ok {
			return a, true
		}
	}
	return Action{}, false
}

func (q *ScriptQueue) popLocked(k queueKey) (Action, bool) {
	queue := q.queues[k]
	if len(queue) == 0 {
		return Action{}, false
	}
	a := queue[0]
	a.remaining--
	if a.remaining <= 0 {
		queue = queue[1:]
	} else {
		queue[0].remaining = a.remaining
	}
	if len(queue) == 0 {
		delete(q.queues, k)
	} else {
		q.queues[k] = queue
	}
	return a, true
}

// QueueSnapshot is one (clientID, endpoint, actions) tuple as returned by
// GET /test/scripts.
type QueueSnapshot struct {
	ClientID string   `json:"client_id"`
	Endpoint string   `json:"endpoint"`
	Actions  []Action `json:"actions"`
}

// Snapshot returns the remaining actions across all queues.
func (q *ScriptQueue) Snapshot() []QueueSnapshot {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]QueueSnapshot, 0, len(q.queues))
	for k, actions := range q.queues {
		out = append(out, QueueSnapshot{
			ClientID: k.clientID,
			Endpoint: k.endpoint,
			Actions:  append([]Action(nil), actions...),
		})
	}
	return out
}

// Clear removes queues matching the filter. Empty fields match anything.
func (q *ScriptQueue) Clear(clientID, endpoint string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for k := range q.queues {
		if clientID != "" && k.clientID != clientID {
			continue
		}
		if endpoint != "" && k.endpoint != endpoint {
			continue
		}
		delete(q.queues, k)
	}
}
