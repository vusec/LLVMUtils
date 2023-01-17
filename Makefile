all:
	cmake -G 'Unix Makefiles' -B build
	cmake --build build -- -j8

clean:
	rm -rf build
	rm -rf bin
	rm -rf lib
