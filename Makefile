RPM := illumio-flowlink-2.0.1-2.x86_64.rpm

.PHONY: original

# Extract the vendor RPM payload into original/ for the local comparison tests
# (needs the vendor RPM in the repo root and bsdtar). original/ is not committed.
original:
	mkdir -p original && bsdtar -xf $(RPM) -C original && chmod -R u+w original
