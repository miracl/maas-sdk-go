package main

type set map[string]struct{}

func newSet() set {
	return set{}
}

func (set set) add(v string) {
	set[v] = struct{}{}
}

func (set set) contains(v string) bool {
	_, ok := set[v]
	return ok
}

func (set set) pop(v string) {
	delete(set, v)
}
