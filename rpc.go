package main

type Args struct {
	Filename  string
	PublicKey int64
	Prime     int64
	Generator int64
	Secret    int64
}

type Reply struct {
	Content   string
	PublicKey int64
	EncKey    string
}
