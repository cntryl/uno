package secret

import (
	"fmt"
	"testing"
)

func TestFormattingIsRedacted(t *testing.T) {
	v := New("do-not-leak")
	if got := fmt.Sprintf("%v %#v", v, v); got != "[REDACTED] secret.Value([REDACTED])" {
		t.Fatal(got)
	}
	v.Destroy()
	if v.Reveal() != "" {
		t.Fatal("destroy did not clear value")
	}
}
