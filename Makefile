all:
	cmake -G 'Unix Makefiles' -B build
	cmake --build build

clean:
	rm -rf build
	rm -rf bin
	rm -rf lib
