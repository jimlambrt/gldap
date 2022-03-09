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
