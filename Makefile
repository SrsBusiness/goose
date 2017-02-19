all:
	go build -o goose *.go

.PHONY: clean
clean:
	rm goose
