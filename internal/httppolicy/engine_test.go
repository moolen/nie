package httppolicy

import "testing"

func TestEngine_EvaluateMatchesHostPortMethodAndPath(t *testing.T) {
	eng, err := New([]Rule{{
		Host:    "api.github.com",
		Port:    443,
		Methods: []string{"GET"},
		Paths:   []string{"/repos/**"},
		Action:  ActionAllow,
	}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	got, ok := eng.Evaluate(Request{
		Host:   "api.github.com",
		Port:   443,
		Method: "GET",
		Path:   "/repos/moolen/nie",
	})
	if !ok || got.Action != ActionAllow {
		t.Fatalf("Evaluate() = %#v, %v; want allow, true", got, ok)
	}
}

func TestEngine_Evaluate_Table(t *testing.T) {
	eng, err := New([]Rule{
		{
			Host:    "*.github.com",
			Port:    443,
			Methods: []string{"GET"},
			Paths:   []string{"/exact"},
			Action:  ActionAllow,
		},
		{
			Host:    "**.github.com",
			Port:    443,
			Methods: []string{"POST"},
			Paths:   []string{"/items/*/details"},
			Action:  ActionAudit,
		},
		{
			Host:    "api.github.com",
			Port:    443,
			Methods: []string{"GET"},
			Paths:   []string{"/repos/**"},
			Action:  ActionAllow,
		},
		{
			Host:    "api.github.com",
			Port:    443,
			Methods: []string{"GET"},
			Paths:   []string{"/repos/**"},
			Action:  ActionDeny,
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		name       string
		req        Request
		wantAction Action
		wantOK     bool
	}{
		{
			name: "host glob single label matches",
			req: Request{
				Host:   "api.github.com",
				Port:   443,
				Method: "GET",
				Path:   "/exact",
			},
			wantAction: ActionAllow,
			wantOK:     true,
		},
		{
			name: "port mismatch does not match",
			req: Request{
				Host:   "api.github.com",
				Port:   80,
				Method: "GET",
				Path:   "/repos/moolen/nie",
			},
			wantOK: false,
		},
		{
			name: "method is normalized to uppercase",
			req: Request{
				Host:   "api.github.com",
				Port:   443,
				Method: "get",
				Path:   "/repos/moolen/nie",
			},
			wantAction: ActionAllow,
			wantOK:     true,
		},
		{
			name: "path exact match",
			req: Request{
				Host:   "foo.github.com",
				Port:   443,
				Method: "GET",
				Path:   "/exact",
			},
			wantAction: ActionAllow,
			wantOK:     true,
		},
		{
			name: "path single segment wildcard matches one segment",
			req: Request{
				Host:   "a.b.github.com",
				Port:   443,
				Method: "POST",
				Path:   "/items/42/details",
			},
			wantAction: ActionAudit,
			wantOK:     true,
		},
		{
			name: "path single segment wildcard does not match deep path",
			req: Request{
				Host:   "a.b.github.com",
				Port:   443,
				Method: "POST",
				Path:   "/items/42/extra/details",
			},
			wantOK: false,
		},
		{
			name: "path double wildcard matches across depth",
			req: Request{
				Host:   "api.github.com",
				Port:   443,
				Method: "GET",
				Path:   "/repos/org/repo/pulls/1",
			},
			wantAction: ActionAllow,
			wantOK:     true,
		},
		{
			name: "first match wins",
			req: Request{
				Host:   "api.github.com",
				Port:   443,
				Method: "GET",
				Path:   "/repos/conflict",
			},
			wantAction: ActionAllow,
			wantOK:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := eng.Evaluate(tt.req)
			if ok != tt.wantOK {
				t.Fatalf("Evaluate() ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if got.Action != tt.wantAction {
				t.Fatalf("Evaluate() action = %q, want %q", got.Action, tt.wantAction)
			}
		})
	}
}

