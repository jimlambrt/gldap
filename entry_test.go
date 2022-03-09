package gldap

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEntry_GetAttributes(t *testing.T) {
	tests := []struct {
		name  string
		entry *Entry
		attr  string
		want  []string
	}{
		{
			name: "empty",
			entry: &Entry{
				Attributes: []*EntryAttribute{},
			},
			want: []string{},
		},
		{
			name: "found",
			entry: &Entry{
				Attributes: []*EntryAttribute{
					NewEntryAttribute("found", []string{"value1", "value2"}),
				},
			},
			attr: "found",
			want: []string{"value1", "value2"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			got := tc.entry.GetAttributeValues(tc.attr)
			assert.Equal(tc.want, got)
		})
	}
}

func TestEntryAttribute_AddValue(t *testing.T) {
	tests := []struct {
		name   string
		attr   *EntryAttribute
		values []string
		want   *EntryAttribute
	}{
		{
			name:   "simple",
			attr:   NewEntryAttribute("simple", []string{"v1"}),
			values: []string{"v2", "v3"},
			want:   NewEntryAttribute("simple", []string{"v1", "v2", "v3"}),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			tc.attr.AddValue(tc.values...)
			assert.Equal(tc.want, tc.attr)
		})
	}
}

func TestEntry_PrettyPrint(t *testing.T) {
	tests := []struct {
		name   string
		entry  *Entry
		writer *strings.Builder
		want   string
	}{
		{
			name: "with-writer",
			entry: &Entry{
				DN: "uid=alice",
				Attributes: []*EntryAttribute{
					NewEntryAttribute("cn", []string{"alice"})},
			},
			writer: new(strings.Builder),
			want:   " DN: uid=alice\n   cn: [alice]\n",
		},
		{
			name: "stdout",
			entry: &Entry{
				DN: "uid=alice",
				Attributes: []*EntryAttribute{
					NewEntryAttribute("cn", []string{"alice"})},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			tc.entry.PrettyPrint(1, WithWriter(tc.writer))
			if !isNil(tc.writer) {
				assert.Equal(tc.want, tc.writer.String())
			}
		})
	}
}
