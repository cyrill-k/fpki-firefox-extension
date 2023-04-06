package main

import "fmt"

func main() {
	fmt.Println("Hello, WebAssembly!")
}

//export test
func test() string {
	fmt.Println("Called test()")
	return "hello, function"
}

//export add
func add(x int, y int) int {
	fmt.Printf("called add with params: %d %d\n", x, y)
	return x + y;
}
