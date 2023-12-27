package cache_v2

import "embed"

// validation outcome
const (
	FAILURE int = iota
	SUCCESS
)

// enable read access to files within embedded directory
//
//go:embed embedded/*
var validationFileSystem embed.FS
