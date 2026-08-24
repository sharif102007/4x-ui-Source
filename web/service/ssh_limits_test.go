package service

import "testing"

func TestParseSSHCounterBytesUsesOneTableDump(t *testing.T) {
	raw := `table inet fourxui_ssh {
        counter user_7_up {
                packets 10 bytes 1200
        }
        counter user_7_down {
                packets 20 bytes 3400
        }
        counter user_11_up {
                packets 1 bytes 55
        }
}`

	totals := parseSSHCounterBytes(raw)
	if totals[7] != 4600 {
		t.Fatalf("user 7 total = %d, want 4600", totals[7])
	}
	if totals[11] != 55 {
		t.Fatalf("user 11 total = %d, want 55", totals[11])
	}
}
