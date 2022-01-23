package scanner

import (
	"io/fs"
	"path/filepath"
)

type Scanner struct {
	Dir        string              // Directory to start scanning
	Extensions map[string]struct{} // Dictionary used to filter file extensions, ignored when empty
	Action     func(path string)   // Action to execute when file is found
}

// Run starts scanning Dir and executes Action for every matching file
func (s Scanner) Run() error {
	return filepath.WalkDir(s.Dir, s.walker)
}

func (s Scanner) walker(path string, d fs.DirEntry, e error) error {
	if e != nil || d.IsDir() {
		return nil // Ignore errors and directories
	}

	// Run Action if extension is in dict or when dict is empty
	if _, ok := s.Extensions[filepath.Ext(d.Name())]; ok || len(s.Extensions) == 0 {
		// Ignore empty files
		if info, err := d.Info(); err == nil && info.Size() > 0 {
			s.Action(path)
		}
	}
	return nil
}
