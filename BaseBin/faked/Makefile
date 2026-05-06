TARGET = launchd

CC = clang

CFLAGS = -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -arch arm64e -miphoneos-version-min=15.0 -fobjc-arc -O2

sign: $(TARGET)
	@ldid -Cadhoc -Sentitlements.plist -Icom.apple.xpc.launchd $<

$(TARGET): $(wildcard src/*.m)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	@rm -f $(TARGET)
