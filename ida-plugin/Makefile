BUILD_DIR ?= build
BUILD_TYPE ?= Release
CMAKE ?= cmake

.PHONY: all configure build clean rebuild help

all: build

configure:
	$(CMAKE) -S . -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=$(BUILD_TYPE)

build: configure
	$(CMAKE) --build $(BUILD_DIR)

clean:
	$(CMAKE) -E rm -rf $(BUILD_DIR)

rebuild: clean build

help:
	@printf '%s\n' \
		'Usage: make [target] [BUILD_DIR=build] [BUILD_TYPE=Release]' \
		'' \
		'Targets:' \
		'  all            Configure and build the plugin' \
		'  configure      Configure the CMake build directory' \
		'  build          Configure and build the plugin' \
		'  clean          Remove the CMake build directory' \
		'  rebuild        Remove build dir, configure, and build' \
		'  help           Show this help'
