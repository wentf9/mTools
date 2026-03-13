package host

import (
	"reflect"
	"testing"
)

func TestAppendUnique(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		val      string
		expected []string
		changed  bool
	}{
		{"append new item", []string{"a", "b"}, "c", []string{"a", "b", "c"}, true},
		{"append existing item", []string{"a", "b", "c"}, "b", []string{"a", "b", "c"}, false},
		{"append to empty slice", []string{}, "a", []string{"a"}, true},
		{"append empty item", []string{"a"}, "", []string{"a"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, changed := appendUnique(tt.slice, tt.val)
			if changed != tt.changed {
				t.Errorf("expected changed %v, got %v", tt.changed, changed)
			}
			if !reflect.DeepEqual(res, tt.expected) {
				t.Errorf("expected result %v, got %v", tt.expected, res)
			}
		})
	}
}
