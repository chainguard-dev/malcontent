package action

import "testing"

func TestCleanPath(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		prefix string
		want   string
	}{
		{
			name:   "linux",
			path:   "/tmp/static3980366648/usr/share/zoneinfo/zone1970",
			prefix: "/tmp/static3980366648/",
			want:   "usr/share/zoneinfo/zone1970",
		},
		{
			name:   "macOS",
			path:   "/var/folders/3g/88131l9j11x995ppjbxsvhbh0000gn/T/apko_0.13.2_linux_arm64.tar.gz2526862474/apko_0.13.2_linux_arm64/apko",
			prefix: "/var/folders/3g/88131l9j11x995ppjbxsvhbh0000gn/T/apko_0.13.2_linux_arm64.tar.gz2526862474/",
			want:   "apko_0.13.2_linux_arm64/apko",
		},
		{
			name:   "windows",
			path:   "C:\\Users\\abc\\AppData\\Local\\Temp\\static3980366648\\usr\\share\\zoneinfo\\zone1970",
			prefix: "C:\\Users\\abc\\AppData\\Local\\Temp\\static3980366648\\",
			want:   "usr\\share\\zoneinfo\\zone1970",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cleanPath(tt.path, tt.prefix); got != tt.want {
				t.Errorf("CleanPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "single separator",
			path: "/apko_0.13.2_linux_arm64/apko",
			want: "apko_0.13.2_linux_arm64/apko",
		},
		{
			name: "multiple separators",
			path: "/usr/share/zoneinfo/zone1970",
			want: "usr/share/zoneinfo/zone1970",
		},
		{
			name: "multiple windows separators",
			path: "\\usr\\share\\zoneinfo\\zone1970",
			want: "usr/share/zoneinfo/zone1970",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatPath(tt.path); got != tt.want {
				t.Errorf("FormatPath() = %v, want %v", got, tt.want)
			}
		})
	}
}
